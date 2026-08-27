from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .urltools import host_allowed, normalize_url


@dataclass(frozen=True)
class CollectorConfig:
    user_agent: str
    request_interval_seconds: float
    timeout_seconds: float
    max_retries: int
    max_depth: int
    max_requests: int
    max_response_bytes: int
    respect_robots: bool
    fetch_query_urls: bool


@dataclass(frozen=True)
class CompanyConfig:
    company_id: str
    company_code: str
    groups: tuple[str, ...]
    enabled: bool
    name: str
    indicator: str
    allowed_domains: tuple[str, ...]
    fetch_domains: tuple[str, ...]
    seed_urls: tuple[str, ...]
    ownership_evidence_urls: tuple[str, ...]
    security_contact: str
    official_repositories: tuple[str, ...] = ()


@dataclass(frozen=True)
class AppConfig:
    collector: CollectorConfig
    companies: tuple[CompanyConfig, ...]

    def get_company(self, company_id: str) -> CompanyConfig:
        company = next(
            (item for item in self.companies if item.company_id == company_id),
            None,
        )
        if company is None:
            raise ValueError(f"설정에 없는 company_id입니다: {company_id}")
        if not company.enabled:
            raise ValueError(
                f"{company_id}는 enabled=false입니다. 자산과 허용 범위를 검증한 후 활성화하세요."
            )
        return company

    def get_group(self, group: str) -> tuple[CompanyConfig, ...]:
        companies = tuple(c for c in self.companies if c.enabled and group in c.groups)
        if not companies:
            raise ValueError(f"활성 기업이 없는 그룹입니다: {group}")
        return companies

    def get_enabled_companies(self) -> tuple[CompanyConfig, ...]:
        companies = tuple(c for c in self.companies if c.enabled)
        if not companies:
            raise ValueError("활성화된 기업이 없습니다.")
        return companies


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    with config_path.open("rb") as config_file:
        raw = tomllib.load(config_file)

    collector_raw = raw.get("collector", {})
    collector = CollectorConfig(
        user_agent=str(collector_raw.get("user_agent", "PublicAssetResearch/0.1")),
        request_interval_seconds=float(
            collector_raw.get("request_interval_seconds", 3.0)
        ),
        timeout_seconds=float(collector_raw.get("timeout_seconds", 10.0)),
        max_retries=int(collector_raw.get("max_retries", 1)),
        max_depth=int(collector_raw.get("max_depth", 1)),
        max_requests=int(collector_raw.get("max_requests", 50)),
        max_response_bytes=int(collector_raw.get("max_response_bytes", 5_000_000)),
        respect_robots=bool(collector_raw.get("respect_robots", True)),
        fetch_query_urls=bool(collector_raw.get("fetch_query_urls", False)),
    )

    companies = tuple(
        CompanyConfig(
            company_id=str(item["company_id"]),
            company_code=str(item.get("company_code", item["company_id"])).upper(),
            groups=tuple(str(x) for x in item.get("groups", [])),
            enabled=bool(item.get("enabled", False)),
            name=str(item["name"]),
            indicator=str(item.get("indicator", item["name"])),
            allowed_domains=tuple(
                str(value).lower().strip(".") for value in item["allowed_domains"]
            ),
            fetch_domains=tuple(
                str(value).lower().strip(".")
                for value in item.get("fetch_domains", [])
            ),
            seed_urls=tuple(str(x) for x in item["seed_urls"]),
            ownership_evidence_urls=tuple(
                str(value)
                for value in item.get("ownership_evidence_urls", [])
            ),
            security_contact=str(item.get("security_contact", "")),
            official_repositories=tuple(
                str(value) for value in item.get("official_repositories", [])
            ),
        )
        for item in raw.get("companies", [])
    )
    app = AppConfig(collector=collector, companies=companies)
    validate_config(app)
    return app


def validate_config(app: AppConfig) -> None:
    collector = app.collector
    if collector.request_interval_seconds < 0:
        raise ValueError("request_interval_seconds는 0 이상이어야 합니다.")
    if (
        collector.timeout_seconds <= 0
        or collector.max_requests <= 0
        or collector.max_response_bytes <= 0
    ):
        raise ValueError("timeout, max_requests, max_response_bytes는 0보다 커야 합니다.")
    if not 0 <= collector.max_retries <= 3:
        raise ValueError("max_retries는 0~3 범위여야 합니다.")
    if not 0 <= collector.max_depth <= 2:
        raise ValueError("안전한 MVP에서는 max_depth를 0~2로 제한합니다.")
    if collector.max_requests > 500:
        raise ValueError("안전한 MVP에서는 max_requests를 500 이하로 제한합니다.")

    ids: set[str] = set()
    codes: set[str] = set()
    for company in app.companies:
        if company.company_id in ids:
            raise ValueError(f"중복 company_id: {company.company_id}")
        ids.add(company.company_id)
        if not re.fullmatch(r"[A-Z0-9]{2,12}", company.company_code):
            raise ValueError(
                f"{company.company_id}: company_code는 2~12자의 영문 대문자와 숫자만 허용합니다."
            )
        if company.company_code in codes:
            raise ValueError(f"중복 company_code: {company.company_code}")
        codes.add(company.company_code)
        if not company.allowed_domains:
            raise ValueError(f"{company.company_id}: allowed_domains가 비어 있습니다.")
        if not set(company.fetch_domains).issubset(set(company.allowed_domains)):
            raise ValueError(
                f"{company.company_id}: fetch_domains는 allowed_domains의 일부여야 합니다. "
                "외부 호스트는 먼저 소유 관계를 검증해 allowed_domains에도 추가하세요."
            )
        if company.enabled and not company.ownership_evidence_urls:
            raise ValueError(
                f"{company.company_id}: 활성 기업에는 "
                "ownership_evidence_urls가 필요합니다."
            )
        if company.enabled and not company.security_contact:
            raise ValueError(
                f"{company.company_id}: 활성 기업에는 security_contact가 필요합니다."
            )
        for seed_url in company.seed_urls:
            try:
                normalized_seed = normalize_url(seed_url)
            except ValueError as exc:
                raise ValueError(
                    f"{company.company_id}: 잘못된 seed_url: {seed_url}"
                ) from exc
            if not host_allowed(normalized_seed, company.fetch_domains):
                raise ValueError(
                    f"{company.company_id}: seed_url 호스트는 fetch_domains에 "
                    f"포함되어야 합니다: {seed_url}"
                )
