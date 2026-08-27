from __future__ import annotations

import json
from collections import deque
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from .config import AppConfig, CompanyConfig
from .discovery import discover_html, discover_robots, discover_sitemap
from .http_client import SafeHttpClient
from .models import Candidate, DiscoveredLink, timestamp_now
from .urltools import (
    content_hint,
    host_allowed,
    is_static_asset,
    normalize_url,
    target_platform,
)


class CollectorPipeline:
    def __init__(self, app: AppConfig, company: CompanyConfig) -> None:
        self.app = app
        self.company = company
        self.client = SafeHttpClient(app.collector, company)
        self._seen_urls: set[str] = set()
        self._seen_contents: set[str] = set()
        self._candidate_keys: set[tuple[str, str, str]] = set()
        self._candidates: list[Candidate] = []
        self._static_assets: list[Candidate] = []
        self._candidate_count = 0
        self._run_date = datetime.now().astimezone().strftime("%Y%m%d")

    def dry_run_summary(self) -> dict[str, object]:
        return {
            "company_id": self.company.company_id,
            "company_name": self.company.name,
            "seed_urls": list(self.company.seed_urls),
            "fetch_domains": list(self.company.fetch_domains),
            "max_depth": self.app.collector.max_depth,
            "max_requests": self.app.collector.max_requests,
            "request_interval_seconds": self.app.collector.request_interval_seconds,
            "respect_robots": self.app.collector.respect_robots,
        }

    def collect(self) -> list[Candidate]:
        queue: deque[tuple[str, int, str, str]] = deque()
        for seed in self.company.seed_urls:
            seed_url = normalize_url(seed)
            queue.append((seed_url, 0, seed_url, "seed"))
            parts = urlsplit(seed_url)
            origin = f"{parts.scheme}://{parts.netloc}"
            queue.extend(
                (
                    (f"{origin}/robots.txt", 0, seed_url, "seed_robots"),
                    (f"{origin}/sitemap.xml", 0, seed_url, "seed_sitemap"),
                )
            )

        while queue and self.client.request_count < self.app.collector.max_requests:
            url, depth, source_url, method = queue.popleft()
            try:
                url = normalize_url(url)
            except ValueError:
                continue
            self._add_candidate(source_url, url, method, content_hint(url))
            if url in self._seen_urls or depth > self.app.collector.max_depth:
                continue
            self._seen_urls.add(url)

            can_fetch, _ = self.client.can_fetch(url)
            if not can_fetch:
                continue
            try:
                response = self.client.fetch(url)
            except Exception:
                continue
            if response.sha256 in self._seen_contents:
                continue
            self._seen_contents.add(response.sha256)

            links = self._discover(
                response.final_url,
                response.content_type,
                response.body,
            )
            for link in links:
                self._add_candidate(
                    link.source_url,
                    link.target_url,
                    link.discovery_method,
                    link.content_hint,
                )
                if (
                    depth < self.app.collector.max_depth
                    and host_allowed(link.target_url, self.company.fetch_domains)
                    and not is_static_asset(link.target_url, link.content_hint)
                ):
                    queue.append(
                        (
                            link.target_url,
                            depth + 1,
                            link.source_url,
                            link.discovery_method,
                        )
                    )
        return self._candidates

    def _discover(
        self,
        url: str,
        content_type_value: str,
        body: bytes,
    ) -> list[DiscoveredLink]:
        hint = content_hint(url, content_type_value)
        if urlsplit(url).path.lower().endswith("/robots.txt"):
            return discover_robots(url, body)
        if hint == "xml" or "xml" in content_type_value.lower():
            return discover_sitemap(url, body)
        if hint == "html" or "html" in content_type_value.lower():
            return discover_html(url, body)
        return []

    def _add_candidate(
        self,
        source_url: str,
        target_url: str,
        method: str,
        hint: str,
    ) -> None:
        try:
            source = normalize_url(source_url)
            target = normalize_url(target_url, source)
        except ValueError:
            return
        key = (source, target, method)
        if key in self._candidate_keys:
            return
        self._candidate_keys.add(key)
        self._candidate_count += 1
        candidate = Candidate(
            candidate_id=(
                f"DIR_{self.company.company_code}_{self._run_date}_"
                f"{self._candidate_count:06d}"
            ),
            track="DIRECT",
            company_name=self.company.name,
            source_platform="official_web",
            source_url=source,
            target_platform=target_platform(target, self.company.allowed_domains),
            target_url=target,
            discovery_method=method,
            matched_indicator=self.company.indicator,
            discovered_at=timestamp_now(),
            content_hint=hint,
        )
        destination = (
            self._static_assets
            if is_static_asset(target, hint)
            else self._candidates
        )
        destination.append(candidate)

    @property
    def static_assets(self) -> list[Candidate]:
        return self._static_assets


def write_jsonl(candidates: list[Candidate], output_path: str | Path) -> None:
    path = Path(output_path)
    with path.open("w", encoding="utf-8", newline="\n") as output_file:
        for candidate in candidates:
            output_file.write(
                json.dumps(
                    candidate.to_dict(),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            output_file.write("\n")


def write_run_summary(
    companies: tuple[CompanyConfig, ...],
    output_path: str | Path,
    run_details: dict[str, dict[str, object]] | None = None,
) -> None:
    path = Path(output_path)
    details = run_details or {}
    lines = [
        "# DIRECT 자산 수집 요약",
        "",
        "- 트랙: `DIRECT`",
        "- 수집 방식: 제3자 공개 색인을 이용한 비직접 수집",
        "- 대상 기업 서버 직접 요청: 없음",
        "",
    ]
    for company in companies:
        company_details = details.get(company.company_id, {})
        lines.extend(
            [
                f"## {company.name} (`{company.company_id}`)",
                "",
                f"- 결과: `{company.company_id}.jsonl`",
                f"- 공식 도메인: {', '.join(company.allowed_domains)}",
                "- 수집 출처: CT, 공개 DNS, Common Crawl, Wayback Machine, "
                "공식 저장소",
            ]
        )
        if company_details:
            lines.extend(
                [
                    f"- 후보 수: {company_details['candidate_count']}",
                    "- 공개 색인 요청 수: "
                    f"{company_details['index_request_count']}",
                    "",
                    "### site: 검색 쿼리",
                    "",
                ]
            )
            queries = company_details.get("search_queries", ())
            lines.extend(f"- `{query}`" for query in queries)
            errors = company_details.get("errors", ())
            if errors:
                lines.extend(["", "### 경고", ""])
                lines.extend(f"- {error}" for error in errors)
        lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
