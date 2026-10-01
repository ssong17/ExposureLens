"""Config loading and validation: a [collector] block and an [[orgs]] list."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")


@dataclass(frozen=True)
class CollectorConfig:
    user_agent: str = "PublicAssetResearch/0.2 (+security-research)"
    request_interval_seconds: float = 2.0
    timeout_seconds: float = 30.0
    max_retries: int = 5
    # Wait before each retry (seconds): 1st, 2nd, ... A retry past the end of the
    # list reuses its last value. Short first wait, then doubling.
    retry_delays_seconds: tuple[float, ...] = (2.0, 4.0, 8.0, 16.0, 32.0)
    # Volume limits: 0 = unlimited (process everything found). There is no
    # truncation cap any more — a run finishes the whole target, pausing between
    # organizations to stay polite instead of cutting work off partway. Per-host
    # request_interval_seconds is what actually protects the free-tier indexes.
    max_requests: int = 0
    max_apex_per_org: int = 0
    max_endpoints_per_org: int = 0
    # Query-string variants of one (host, path) to keep, e.g. board.php?idx=1,
    # ?idx=2, ?page=9 … They render the same page and rarely differ in exposed
    # secrets, so a few are enough. 0 = unlimited (keep every variant).
    max_endpoint_variants_per_path: int = 5
    resolve_timeout: float = 3.0
    resolve_workers: int = 20
    # Seconds to rest between organizations (0 = no pause). Sequential-with-rest
    # replaces the old request cap: it lets a big run complete without hammering
    # crt.sh/Wayback/urlscan into rate-limiting the whole thing.
    org_pause_seconds: float = 5.0
    # Index responses (crt.sh org search for a large org is genuinely big).
    max_response_bytes: int = 8_000_000
    # Bodies read for content rules. Separate and much smaller: a secret lives in
    # the first few hundred KB, and the old shared 30MB cap meant one probe could
    # pull 30MB into memory and run every regex over it.
    max_body_bytes: int = 1_000_000
    urlscan_limit: int = 100
    # Per-apex cap for search-engine discovery (--search). 0 keeps it off even
    # when the flag is set; API keys come from env (see sources.search).
    search_limit: int = 20
    # Search queries (templates with {apex}, or bare keywords wrapped as
    # site:apex "kw"). Empty = sources.search.DEFAULT_QUERIES. Override per
    # target to hunt specific terms (관리자, 백업, a CMS name, ...).
    search_queries: tuple[str, ...] = ()
    # Wayback is swept with CDX pagination (every subdomain, no 1000-row gap).
    # This caps how many pages one apex may pull (0 = all pages). Pagination
    # already keeps request counts low, so the default pulls everything.
    wayback_max_pages: int = 0
    # Bounded parsed-JSON cache (entries).
    cache_entries: int = 128


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


def _load_raw(path: Path) -> dict:
    """Read config from a single .toml file OR a directory of them.

    A directory (the preferred layout) holds one file per organization plus a
    shared collector file:

        config/
          _collector.toml   -> [collector] block
          ncsoft.toml        -> [[orgs]] (one) or top-level org fields
          cafe24.toml
          ...

    Every file's [collector] is merged (later files win per key) and every
    file's orgs are concatenated, so splitting the old single config.toml into
    one-file-per-org changes nothing about the result.
    """
    if not path.is_dir():
        with path.open("rb") as handle:
            return tomllib.load(handle)

    # *.example.toml is a format sample, so it is excluded from loading.
    files = sorted(
        p for p in path.glob("*.toml")
        if p.is_file() and ".example." not in p.name
    )
    if not files:
        raise ValueError(f"config 폴더에 .toml 파일이 없습니다: {path}")
    collector: dict = {}
    orgs: list = []
    for f in files:
        with f.open("rb") as handle:
            raw = tomllib.load(handle)
        if isinstance(raw.get("collector"), dict):
            collector.update(raw["collector"])
        orgs.extend(raw.get("orgs", []))
        # A per-org file may also put the org fields at the top level instead of
        # under [[orgs]]; treat that as a single org.
        if "org_id" in raw:
            orgs.append(
                {k: v for k, v in raw.items() if k not in ("collector", "orgs")}
            )
    return {"collector": collector, "orgs": orgs}


def load_config(path: str | Path) -> AppConfig:
    raw = _load_raw(Path(path))

    c = raw.get("collector", {})

    def _num(key, cast, default):
        try:
            return cast(c.get(key, default))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"[collector] {key} 값이 잘못되었습니다: {exc}") from exc

    def _delays(value) -> tuple[float, ...]:
        if value is None:
            return CollectorConfig.retry_delays_seconds
        if not isinstance(value, list) or not value:
            raise ValueError("[collector] retry_delays_seconds는 숫자 목록이어야 합니다 (예: [5, 15, 30]).")
        try:
            return tuple(float(v) for v in value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"[collector] retry_delays_seconds 값이 잘못되었습니다: {exc}") from exc

    collector = CollectorConfig(
        user_agent=str(c.get("user_agent", CollectorConfig.user_agent)),
        request_interval_seconds=_num(
            "request_interval_seconds", float,
            CollectorConfig.request_interval_seconds,
        ),
        timeout_seconds=_num("timeout_seconds", float, CollectorConfig.timeout_seconds),
        max_retries=_num("max_retries", int, CollectorConfig.max_retries),
        retry_delays_seconds=_delays(c.get("retry_delays_seconds")),
        max_requests=_num("max_requests", int, CollectorConfig.max_requests),
        org_pause_seconds=_num(
            "org_pause_seconds", float, CollectorConfig.org_pause_seconds
        ),
        max_response_bytes=_num(
            "max_response_bytes", int, CollectorConfig.max_response_bytes
        ),
        max_body_bytes=_num("max_body_bytes", int, CollectorConfig.max_body_bytes),
        max_apex_per_org=_num(
            "max_apex_per_org", int, CollectorConfig.max_apex_per_org
        ),
        max_endpoints_per_org=_num(
            "max_endpoints_per_org", int, CollectorConfig.max_endpoints_per_org
        ),
        max_endpoint_variants_per_path=_num(
            "max_endpoint_variants_per_path", int,
            CollectorConfig.max_endpoint_variants_per_path,
        ),
        resolve_timeout=_num("resolve_timeout", float, CollectorConfig.resolve_timeout),
        resolve_workers=_num("resolve_workers", int, CollectorConfig.resolve_workers),
        urlscan_limit=_num("urlscan_limit", int, CollectorConfig.urlscan_limit),
        search_limit=_num("search_limit", int, CollectorConfig.search_limit),
        search_queries=tuple(str(q) for q in c.get("search_queries", [])),
        wayback_max_pages=_num(
            "wayback_max_pages", int, CollectorConfig.wayback_max_pages
        ),
        cache_entries=_num("cache_entries", int, CollectorConfig.cache_entries),
    )

    orgs = []
    for index, item in enumerate(raw.get("orgs", []), 1):
        if not isinstance(item, dict):
            raise ValueError(f"{index}번째 [[orgs]] 항목이 테이블이 아닙니다.")
        for required in ("org_id", "name"):
            if required not in item:
                raise ValueError(
                    f"{index}번째 [[orgs]] 항목에 필수 키 '{required}'가 없습니다."
                )
        orgs.append(
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
        )

    app = AppConfig(collector=collector, orgs=tuple(orgs))
    validate_config(app)
    return app


def validate_config(app: AppConfig) -> None:
    col = app.collector
    if col.request_interval_seconds < 0:
        raise ValueError("request_interval_seconds는 0 이상이어야 합니다.")
    if col.timeout_seconds <= 0 or col.max_response_bytes <= 0:
        raise ValueError("timeout_seconds와 max_response_bytes는 0보다 커야 합니다.")
    if col.max_body_bytes <= 0:
        raise ValueError("max_body_bytes는 0보다 커야 합니다.")
    if col.max_body_bytes > col.max_response_bytes:
        raise ValueError("max_body_bytes는 max_response_bytes 이하여야 합니다.")
    if not 0 <= col.max_retries <= 5:
        raise ValueError("max_retries는 0~5 범위여야 합니다.")
    if any(d < 0 for d in col.retry_delays_seconds):
        raise ValueError("retry_delays_seconds는 모두 0 이상이어야 합니다.")
    # 0 = unlimited for all three volume limits.
    if col.max_requests < 0:
        raise ValueError("max_requests는 0 이상이어야 합니다 (0 = 무제한).")
    if col.max_apex_per_org < 0:
        raise ValueError("max_apex_per_org는 0 이상이어야 합니다 (0 = 무제한).")
    if col.max_endpoints_per_org < 0:
        raise ValueError("max_endpoints_per_org는 0 이상이어야 합니다 (0 = 무제한).")
    if col.max_endpoint_variants_per_path < 0:
        raise ValueError("max_endpoint_variants_per_path는 0 이상이어야 합니다 (0 = 무제한).")
    if col.org_pause_seconds < 0:
        raise ValueError("org_pause_seconds는 0 이상이어야 합니다.")
    if col.urlscan_limit < 0 or col.search_limit < 0 or col.wayback_max_pages < 0:
        raise ValueError("urlscan_limit·search_limit·wayback_max_pages는 0 이상이어야 합니다.")
    if col.cache_entries < 0:
        raise ValueError("cache_entries는 0 이상이어야 합니다.")
    if col.resolve_timeout <= 0 or col.resolve_workers < 1:
        raise ValueError("resolve_timeout>0, resolve_workers>=1 이어야 합니다.")

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
        # org_type is only a hint for apex discovery's TLD-class match; an
        # unknown value just means "no hint" (see tldclass.expected_classes).
        # So any non-empty string is allowed — the Notion export uses free-form
        # category names like "IT & Software", and rejecting those is wrong.
        if not org.org_type:
            raise ValueError(f"{org.org_id}: org_type이 비어 있습니다.")
