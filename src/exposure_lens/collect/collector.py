"""Collector: apex discovery -> subdomains + endpoints -> resolve -> ASN.

Subdomains come from crt.sh and, as a fallback, Wayback hostnames; endpoints
come from Wayback URLs. Only high/medium apexes are enumerated, capped per org.
Resolution runs off the request budget; ASN enrichment covers unique IPs only.
"""
from __future__ import annotations

import re
from typing import Callable
from urllib.parse import urlsplit

from ..apex.discovery import discover_apex
from ..core.config import CollectorConfig, OrgConfig
from ..core.models import ApexCandidate, Asset, run_date, timestamp_now
from ..core.net import Http, RequestBudgetExceeded
from ..sources import crtsh, cymru, wayback
from .resolve import resolve_hosts

_ID_SANITIZE = re.compile(r"[^A-Z0-9]+")
TARGET_CONFIDENCES = ("high", "medium")
_RANK = {"high": 0, "medium": 1}

# Media/style files that rarely hold secrets are dropped from endpoints.
_STATIC_EXT = frozenset(
    "jpg jpeg png gif ico svg webp bmp css woff woff2 ttf eot otf "
    "mp4 mp3 avi mov webm ogg".split()
)


def _prefix(org_id: str) -> str:
    return _ID_SANITIZE.sub("_", org_id.upper()).strip("_") or "ORG"


def _in_scope(host: str, apex: str) -> bool:
    return host == apex or host.endswith(f".{apex}")


def _is_endpoint(url: str) -> bool:
    path = urlsplit(url).path
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    return ext not in _STATIC_EXT


def select_target_apexes(
    candidates: list[ApexCandidate], limit: int
) -> list[ApexCandidate]:
    targets = [c for c in candidates if c.confidence in TARGET_CONFIDENCES]
    targets.sort(key=lambda c: (_RANK[c.confidence], -c.cert_count))
    return targets[:limit]


def collect_org(
    http: Http,
    org: OrgConfig,
    collector: CollectorConfig,
    *,
    resolve: bool = True,
    endpoints: bool = True,
    log: Callable[[str], None] | None = None,
) -> tuple[list[Asset], list[str]]:
    """Return (assets, problems) for one organization."""
    say = log or (lambda _: None)
    say(f"[{org.org_id}] discovering apex...")
    candidates, errors = discover_apex(http, org)
    problems = [f"[{org.org_id}] {e}" for e in errors]
    if not candidates:
        problems.append(f"[{org.org_id}] no apex candidates")
        return [], problems

    targets = select_target_apexes(candidates, collector.max_apex_per_org)
    say(f"[{org.org_id}] apex: {len(candidates)} candidates, {len(targets)} to collect")
    eligible = sum(1 for c in candidates if c.confidence in TARGET_CONFIDENCES)
    if eligible > len(targets):
        problems.append(
            f"[{org.org_id}] capped apexes {len(targets)}/{eligible} (max_apex_per_org)"
        )

    # host -> (apex, confidence); first apex to claim a host wins.
    host_apex: dict[str, tuple[str, str]] = {}
    endpoint_rows: list[tuple[str, str, str, str]] = []  # (apex, conf, url, host)
    endpoint_urls: set[str] = set()

    for i, cand in enumerate(targets, 1):
        say(f"[{org.org_id}] ({i}/{len(targets)}) {cand.apex} crt.sh/wayback...")
        try:
            for host in crtsh.domain_search(http, cand.apex):
                host_apex.setdefault(host, (cand.apex, cand.confidence))
        except RequestBudgetExceeded as exc:
            problems.append(f"[{org.org_id}] stopped at request cap: {exc}")
            break
        except Exception as exc:  # noqa: BLE001 - report source failures in summary
            problems.append(f"[{org.org_id}] crt.sh %.{cand.apex}: {exc}")

        if not endpoints:
            continue
        try:
            urls = wayback.fetch_urls(http, cand.apex)
        except RequestBudgetExceeded as exc:
            problems.append(f"[{org.org_id}] stopped at request cap: {exc}")
            break
        except Exception as exc:  # noqa: BLE001
            problems.append(f"[{org.org_id}] wayback {cand.apex}: {exc}")
            continue
        for url in urls:
            host = (urlsplit(url).hostname or "").lower()
            if not host or not _in_scope(host, cand.apex):
                continue
            host_apex.setdefault(host, (cand.apex, cand.confidence))  # backup source
            if (
                _is_endpoint(url)
                and url not in endpoint_urls
                and len(endpoint_rows) < collector.max_endpoints_per_org
            ):
                endpoint_urls.add(url)
                endpoint_rows.append((cand.apex, cand.confidence, url, host))

    ip_map = {}
    asn_map = {}
    if resolve:
        say(f"[{org.org_id}] resolving {len(host_apex)} hosts...")
        ip_map = resolve_hosts(
            list(host_apex),
            timeout=collector.resolve_timeout,
            workers=collector.resolve_workers,
        )
        unique_ips = {ip for ip in ip_map.values() if ip}
        say(f"[{org.org_id}] ASN lookup for {len(unique_ips)} IPs...")
        asn_map = cymru.annotate(http, unique_ips)

    date = run_date()
    prefix = _prefix(org.org_id)
    at = timestamp_now()
    assets: list[Asset] = []

    def _add(asset_type: str, apex: str, conf: str, host: str, url: str = "") -> None:
        ip = ip_map.get(host, "")
        assets.append(
            Asset(
                record_id=f"{prefix}_{date}_{len(assets) + 1:06d}",
                org_id=org.org_id,
                apex=apex,
                apex_confidence=conf,  # type: ignore[arg-type]
                asset_type=asset_type,  # type: ignore[arg-type]
                host=host,
                source="crt.sh+wayback" if asset_type != "endpoint" else "wayback",
                discovered_at=at,
                url=url,
                resolved_ip=ip,
                asn=asn_map.get(ip, ""),
            )
        )

    for host in sorted(host_apex):
        apex, conf = host_apex[host]
        _add("apex" if host == apex else "subdomain", apex, conf, host)
    for apex, conf, url, host in endpoint_rows:
        _add("endpoint", apex, conf, host, url)

    if not assets:
        problems.append(f"[{org.org_id}] no assets collected")
    say(f"[{org.org_id}] done: {len(assets)} assets")
    return assets, problems
