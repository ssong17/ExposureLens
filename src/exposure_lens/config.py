"""Config loading and validation: a [collector] block and an [[orgs]] list."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

VALID_ORG_TYPES = frozenset(
    {"company", "gov", "school", "nonprofit", "research", "other"}
)
_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")


@dataclass(frozen=True)
class CollectorConfig:
    user_agent: str = "PublicAssetResearch/0.2 (+security-research)"
    request_interval_seconds: float = 2.0
    timeout_seconds: float = 30.0
    max_retries: int = 1
    max_requests: int = 300
    max_apex_per_org: int = 25
    max_response_bytes: int = 30_000_000


@dataclass(frozen=True)
class OrgConfig:
    org_id: str
    name: str
    org_type: str
    enabled: bool = False
    groups: tuple[str, ...] = ()
    search_names: tuple[str, ...] = ()
    seed_domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class AppConfig:
    collector: CollectorConfig
    orgs: tuple[OrgConfig, ...] = field(default_factory=tuple)

    def get_org(self, org_id: str) -> OrgConfig:
        org = next((o for o in self.orgs if o.org_id == org_id), None)
        if org is None:
            raise ValueError(f"설정에 없는 org_id입니다: {org_id}")
        if not org.enabled:
            raise ValueError(f"{org_id}는 enabled=false입니다.")
        return org

    def get_group(self, group: str) -> tuple[OrgConfig, ...]:
        orgs = tuple(o for o in self.orgs if o.enabled and group in o.groups)
        if not orgs:
            raise ValueError(f"활성 기관이 없는 그룹입니다: {group}")
        return orgs

    def get_enabled(self) -> tuple[OrgConfig, ...]:
        orgs = tuple(o for o in self.orgs if o.enabled)
        if not orgs:
            raise ValueError("활성화된 기관이 없습니다.")
        return orgs


def load_config(path: str | Path) -> AppConfig:
    with Path(path).open("rb") as handle:
        raw = tomllib.load(handle)

    c = raw.get("collector", {})
    collector = CollectorConfig(
        user_agent=str(c.get("user_agent", CollectorConfig.user_agent)),
        request_interval_seconds=float(
            c.get("request_interval_seconds", CollectorConfig.request_interval_seconds)
        ),
        timeout_seconds=float(c.get("timeout_seconds", CollectorConfig.timeout_seconds)),
        max_retries=int(c.get("max_retries", CollectorConfig.max_retries)),
        max_requests=int(c.get("max_requests", CollectorConfig.max_requests)),
        max_response_bytes=int(
            c.get("max_response_bytes", CollectorConfig.max_response_bytes)
        ),
        max_apex_per_org=int(
            c.get("max_apex_per_org", CollectorConfig.max_apex_per_org)
        ),
    )

    orgs = tuple(
        OrgConfig(
            org_id=str(item["org_id"]).lower(),
            name=str(item["name"]),
            org_type=str(item.get("org_type", "other")).lower(),
            enabled=bool(item.get("enabled", False)),
            groups=tuple(str(x) for x in item.get("groups", [])),
            search_names=tuple(str(x) for x in item.get("search_names", [])),
            seed_domains=tuple(
                str(x).lower().strip(".") for x in item.get("seed_domains", [])
            ),
        )
        for item in raw.get("orgs", [])
    )

    app = AppConfig(collector=collector, orgs=orgs)
    validate_config(app)
    return app


def validate_config(app: AppConfig) -> None:
    col = app.collector
    if col.request_interval_seconds < 0:
        raise ValueError("request_interval_seconds는 0 이상이어야 합니다.")
    if col.timeout_seconds <= 0 or col.max_response_bytes <= 0:
        raise ValueError("timeout_seconds와 max_response_bytes는 0보다 커야 합니다.")
    if not 0 <= col.max_retries <= 3:
        raise ValueError("max_retries는 0~3 범위여야 합니다.")
    if not 1 <= col.max_requests <= 2000:
        raise ValueError("max_requests는 1~2000 범위여야 합니다.")
    if not 1 <= col.max_apex_per_org <= 200:
        raise ValueError("max_apex_per_org는 1~200 범위여야 합니다.")

    seen: set[str] = set()
    for org in app.orgs:
        if not _ID_RE.fullmatch(org.org_id):
            raise ValueError(
                f"잘못된 org_id: {org.org_id} (영소문자/숫자/_/-, 32자 이내)"
            )
        if org.org_id in seen:
            raise ValueError(f"중복 org_id: {org.org_id}")
        seen.add(org.org_id)
        if not org.name.strip():
            raise ValueError(f"{org.org_id}: name이 비어 있습니다.")
        if org.org_type not in VALID_ORG_TYPES:
            raise ValueError(
                f"{org.org_id}: org_type은 {sorted(VALID_ORG_TYPES)} 중 하나여야 합니다."
            )
