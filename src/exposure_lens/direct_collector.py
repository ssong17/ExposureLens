from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any, Callable
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .config import AppConfig, CompanyConfig
from .models import Candidate, timestamp_now
from .urltools import content_hint, host_allowed, normalize_url, target_platform

JsonFetcher = Callable[[str], Any]

SEARCH_TERMS = (
    "",
    "api",
    "swagger",
    "openapi",
    "graphql",
    "filetype:json",
    "filetype:yaml",
    "filetype:pdf",
    "filetype:js",
    "filetype:map",
    "staging",
)


class DirectAssetCollector:
    """Collect company-owned URL candidates from public indexes."""

    def __init__(
        self,
        app: AppConfig,
        company: CompanyConfig,
        fetch_json: JsonFetcher | None = None,
    ) -> None:
        self.app = app
        self.company = company
        self._fetch_json = fetch_json or self._request_json
        self._seen_urls: set[str] = set()
        self._candidates: list[Candidate] = []
        self._errors: list[str] = []
        self._request_count = 0
        self._last_request_at = 0.0
        self._run_date = datetime.now().astimezone().strftime("%Y%m%d")

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(self._errors)

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def search_queries(self) -> tuple[str, ...]:
        return tuple(
            f"site:{domain} {term}".rstrip()
            for domain in self._root_domains()
            for term in SEARCH_TERMS
        )

    def dry_run_summary(self) -> dict[str, object]:
        return {
            "company_id": self.company.company_id,
            "company_name": self.company.name,
            "official_domains": list(self.company.allowed_domains),
            "official_repositories": list(self.company.official_repositories),
            "sources": [
                "certificate_transparency",
                "public_dns",
                "site_search_queries",
                "common_crawl",
                "wayback_machine",
                "official_repositories",
            ],
            "direct_target_requests": False,
        }

    def collect(self) -> list[Candidate]:
        for seed_url in self.company.seed_urls:
            self._add_candidate(
                seed_url,
                seed_url,
                "official_domain_config",
            )
        for repository_url in self.company.official_repositories:
            self._add_candidate(
                repository_url,
                repository_url,
                "official_repository",
            )

        for domain in self._root_domains():
            self._collect_ct(domain)
            self._collect_dns(domain)
            self._collect_common_crawl(domain)
            self._collect_wayback(domain)
        return self._candidates

    def _collect_ct(self, domain: str) -> None:
        source_url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        data = self._safe_fetch(source_url, "certificate_transparency")
        if not isinstance(data, list):
            query = urlencode(
                {
                    "domain": domain,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                }
            )
            source_url = f"https://api.certspotter.com/v1/issuances?{query}"
            data = self._safe_fetch(source_url, "certificate_transparency_fallback")
        if not isinstance(data, list):
            return
        for entry in data:
            if not isinstance(entry, dict):
                continue
            names = entry.get("dns_names")
            hosts = names if isinstance(names, list) else str(
                entry.get("name_value", "")
            ).splitlines()
            for host_value in hosts:
                host = str(host_value)
                host = host.lower().removeprefix("*.").strip().rstrip(".")
                if host and host_allowed(f"https://{host}/", (domain,)):
                    self._add_candidate(source_url, f"https://{host}/", "ct_log")

    def _collect_dns(self, domain: str) -> None:
        for record_type in ("A", "AAAA", "CNAME", "MX", "TXT"):
            query = urlencode({"name": domain, "type": record_type})
            source_url = f"https://dns.google/resolve?{query}"
            data = self._safe_fetch(source_url, "public_dns")
            if not isinstance(data, dict):
                continue
            for answer in data.get("Answer", []):
                if not isinstance(answer, dict):
                    continue
                value = str(answer.get("data", "")).strip('"').rstrip(".")
                if value and "." in value and " " not in value:
                    host = value.split()[-1]
                    if host_allowed(f"https://{host}/", self.company.allowed_domains):
                        self._add_candidate(
                            source_url,
                            f"https://{host}/",
                            "public_dns",
                        )

    def _collect_common_crawl(self, domain: str) -> None:
        indexes = self._safe_fetch(
            "https://index.commoncrawl.org/collinfo.json",
            "common_crawl",
        )
        if not isinstance(indexes, list) or not indexes:
            return
        index_api = str(indexes[0].get("cdx-api", ""))
        if not index_api:
            return
        query = urlencode(
            {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "url,mime",
                "filter": "status:200",
                "collapse": "urlkey",
            }
        )
        source_url = f"{index_api}?{query}"
        data = self._safe_fetch(source_url, "common_crawl", json_lines=True)
        if not isinstance(data, list):
            return
        for entry in data:
            if isinstance(entry, dict):
                self._add_candidate(
                    source_url,
                    str(entry.get("url", "")),
                    "common_crawl",
                    str(entry.get("mime", "")),
                )

    def _collect_wayback(self, domain: str) -> None:
        earliest_year = int(self._run_date[:4]) - 2
        query = urlencode(
            {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original,mimetype",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "from": str(earliest_year),
                "limit": "1000",
            }
        )
        source_url = f"https://web.archive.org/cdx/search/cdx?{query}"
        data = self._safe_fetch(source_url, "wayback_machine")
        if not isinstance(data, list) or len(data) < 2:
            return
        for row in data[1:]:
            if isinstance(row, list) and row:
                mime = str(row[1]) if len(row) > 1 else ""
                self._add_candidate(source_url, str(row[0]), "wayback", mime)

    def _add_candidate(
        self,
        source_url: str,
        target_url: str,
        method: str,
        content_type: str = "",
    ) -> None:
        try:
            target = normalize_url(target_url)
        except ValueError:
            return
        if not host_allowed(target, self.company.allowed_domains):
            return
        if target in self._seen_urls:
            return
        self._seen_urls.add(target)
        self._candidates.append(
            Candidate(
                candidate_id=(
                    f"DIR_{self.company.company_code}_{self._run_date}_"
                    f"{len(self._candidates) + 1:06d}"
                ),
                track="DIRECT",
                company_name=self.company.name,
                source_platform=method,
                source_url=source_url,
                target_platform=target_platform(
                    target,
                    self.company.allowed_domains,
                ),
                target_url=target,
                discovery_method=method,
                matched_indicator=self.company.indicator,
                discovered_at=timestamp_now(),
                content_hint=content_hint(target, content_type),
            )
        )

    def _safe_fetch(
        self,
        url: str,
        source: str,
        *,
        json_lines: bool = False,
    ) -> Any:
        try:
            data = self._fetch_json(url)
            if json_lines and isinstance(data, str):
                return [json.loads(line) for line in data.splitlines() if line]
            return data
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            self._errors.append(f"{source}: {exc}")
            return None

    def _request_json(self, url: str) -> Any:
        body: bytes | None = None
        content_type_value = ""
        last_error: OSError | None = None
        for attempt in range(self.app.collector.max_retries + 1):
            if self._request_count >= self.app.collector.max_requests:
                raise RuntimeError("공개 색인 최대 요청 수에 도달했습니다.")
            delay = self.app.collector.request_interval_seconds - (
                time.monotonic() - self._last_request_at
            )
            if delay > 0:
                time.sleep(delay)
            request = Request(
                url,
                headers={"User-Agent": self.app.collector.user_agent},
                method="GET",
            )
            self._request_count += 1
            try:
                with urlopen(
                    request,
                    timeout=self.app.collector.timeout_seconds,
                ) as response:
                    body = response.read(self.app.collector.max_response_bytes + 1)
                    content_type_value = response.headers.get("Content-Type", "")
                break
            except OSError as exc:
                last_error = exc
                if attempt >= self.app.collector.max_retries:
                    raise
            finally:
                self._last_request_at = time.monotonic()
        if body is None:
            if last_error is not None:
                raise last_error
            raise OSError("공개 색인에서 응답을 받지 못했습니다.")
        if len(body) > self.app.collector.max_response_bytes:
            raise ValueError("공개 색인 응답 크기 제한을 초과했습니다.")
        text = body.decode("utf-8", errors="replace")
        if "application/x-ndjson" in content_type_value:
            return text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            if "\n" in text:
                return text
            raise

    def _root_domains(self) -> tuple[str, ...]:
        return tuple(
            domain
            for domain in self.company.allowed_domains
            if not any(
                domain != other and domain.endswith(f".{other}")
                for other in self.company.allowed_domains
            )
        )
