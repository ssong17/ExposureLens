from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.robotparser import RobotFileParser

from .config import CollectorConfig, CompanyConfig
from .urltools import ensure_public_host, host_allowed, normalize_url


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str
    status: int
    content_type: str
    body: bytes
    sha256: str


class AllowlistRedirectHandler(HTTPRedirectHandler):
    def __init__(self, domains: tuple[str, ...]) -> None:
        super().__init__()
        self.domains = domains

    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ):
        normalized = normalize_url(newurl, req.full_url)
        if not host_allowed(normalized, self.domains):
            raise PermissionError("리다이렉트가 fetch_domains 밖으로 이동했습니다.")
        ensure_public_host(normalized)
        return super().redirect_request(req, fp, code, msg, headers, normalized)


class SafeHttpClient:
    def __init__(self, collector: CollectorConfig, company: CompanyConfig) -> None:
        self.collector = collector
        self.company = company
        self._opener = build_opener(AllowlistRedirectHandler(company.fetch_domains))
        self._last_request_at = 0.0
        self._robots: dict[str, RobotFileParser] = {}
        self.request_count = 0

    def can_fetch(self, url: str) -> tuple[bool, str]:
        normalized = normalize_url(url)
        if not host_allowed(normalized, self.company.fetch_domains):
            return False, "fetch_domains 밖의 호스트"
        if urlsplit(normalized).query and not self.collector.fetch_query_urls:
            return False, "쿼리 URL 요청 비활성화"
        if self.request_count >= self.collector.max_requests:
            return False, "최대 요청 수 도달"
        if self.collector.respect_robots and not self._robots_allowed(normalized):
            return False, "robots.txt 제한"
        return True, "허용"

    def fetch(self, url: str, *, check_robots: bool = True) -> FetchResult:
        normalized = normalize_url(url)
        if not host_allowed(normalized, self.company.fetch_domains):
            raise ValueError("fetch_domains 밖의 URL입니다.")
        if urlsplit(normalized).query and not self.collector.fetch_query_urls:
            raise ValueError("쿼리 URL 요청이 비활성화되어 있습니다.")
        if self.request_count >= self.collector.max_requests:
            raise RuntimeError("최대 요청 수에 도달했습니다.")
        ensure_public_host(normalized)
        should_check_robots = check_robots and self.collector.respect_robots
        if should_check_robots and not self._robots_allowed(normalized):
            raise PermissionError("robots.txt에서 요청을 허용하지 않습니다.")

        last_error: Exception | None = None
        for attempt in range(self.collector.max_retries + 1):
            self._rate_limit()
            request = Request(
                normalized,
                headers={"User-Agent": self.collector.user_agent},
                method="GET",
            )
            self.request_count += 1
            try:
                with self._opener.open(
                    request,
                    timeout=self.collector.timeout_seconds,
                ) as response:
                    final_url = normalize_url(response.geturl())
                    if not host_allowed(final_url, self.company.fetch_domains):
                        raise PermissionError("리다이렉트가 fetch_domains 밖으로 이동했습니다.")
                    ensure_public_host(final_url)
                    body = response.read(self.collector.max_response_bytes + 1)
                    if len(body) > self.collector.max_response_bytes:
                        raise ValueError("응답 크기 제한을 초과했습니다.")
                    return FetchResult(
                        requested_url=normalized,
                        final_url=final_url,
                        status=int(response.status),
                        content_type=response.headers.get("Content-Type", ""),
                        body=body,
                        sha256=hashlib.sha256(body).hexdigest(),
                    )
            except (HTTPError, URLError, TimeoutError) as exc:
                last_error = exc
                if attempt >= self.collector.max_retries:
                    break
        assert last_error is not None
        raise last_error

    def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        delay = self.collector.request_interval_seconds - elapsed
        if delay > 0:
            time.sleep(delay)
        self._last_request_at = time.monotonic()

    def _robots_allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self._robots:
            parser = RobotFileParser()
            robots_url = f"{origin}/robots.txt"
            parser.set_url(robots_url)
            try:
                result = self.fetch(robots_url, check_robots=False)
                parser.parse(result.body.decode("utf-8", errors="replace").splitlines())
            except Exception:
                # robots.txt를 확인하지 못한 경우 보수적으로 일반 페이지만 허용한다.
                parser.parse(["User-agent: *", "Disallow:"])
            self._robots[origin] = parser
        return self._robots[origin].can_fetch(self.collector.user_agent, url)
