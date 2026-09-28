"""Collector: apex discovery -> subdomains + endpoints -> resolve -> ASN.

Subdomains come from crt.sh and, as a fallback, Wayback hostnames; endpoints
come from Wayback URLs. Only high/medium apexes are enumerated, capped per org.
Resolution runs off the request budget; ASN enrichment covers unique IPs only.
"""
from __future__ import annotations

import re
from typing import Callable
from urllib.parse import urlsplit

from .discovery import discover_apex
from ..core.config import CollectorConfig, OrgConfig
from ..core.models import (
    CONFIDENCE_ORDER,
    ApexCandidate,
    Asset,
    run_date,
    timestamp_now,
)
from ..core.net import Http, RequestBudgetExceeded
from ..sources import crtsh, cymru, urlscan, wayback
from .resolve import resolve_hosts

_ID_SANITIZE = re.compile(r"[^A-Z0-9]+")
TARGET_CONFIDENCES = ("high", "medium")

# Media/style files that rarely hold secrets are dropped from endpoints.
_STATIC_EXT = frozenset(
    "jpg jpeg png gif ico svg webp bmp css woff woff2 ttf eot otf "
    "mp4 mp3 avi mov webm ogg".split()
)


def _prefix(org_id: str) -> str:
    return _ID_SANITIZE.sub("_", org_id.upper()).strip("_") or "ORG"


def _valid_host(host: str) -> bool:
    """Reject malformed hosts (empty labels, over-long labels) that crash IDNA."""
    if not host or len(host) > 253:
        return False
    labels = host.split(".")
    return all(0 < len(lbl) <= 63 for lbl in labels)


def _in_scope(host: str, apex: str) -> bool:
    if not _valid_host(host):
        return False
    return host == apex or host.endswith(f".{apex}")


def _is_endpoint(url: str) -> bool:
    path = urlsplit(url).path
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    return ext not in _STATIC_EXT


def select_target_apexes(
    candidates: list[ApexCandidate], limit: int
) -> list[ApexCandidate]:
    targets = [c for c in candidates if c.confidence in TARGET_CONFIDENCES]
    targets.sort(key=lambda c: (CONFIDENCE_ORDER[c.confidence], -c.cert_count))
    return targets[:limit] if limit else targets  # limit 0 = 무제한


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
    # url -> (apex, conf, host, endpoint_source, last_seen)
    endpoint_meta: dict[str, tuple[str, str, str, str, str]] = {}

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

        def _ingest(obs: list[dict], src: str) -> None:
            for o in obs:
                url = o["url"]
                host = (urlsplit(url).hostname or "").lower()
                if not host or not _in_scope(host, cand.apex):
                    continue
                host_apex.setdefault(host, (cand.apex, cand.confidence))
                if not _is_endpoint(url):
                    continue
                prev = endpoint_meta.get(url)
                # urlscan (present-tense) upgrades a wayback-only entry; keep the
                # more recent last_seen.
                if prev is None:
                    # max_endpoints_per_org 0 = 무제한
                    if (collector.max_endpoints_per_org
                            and len(endpoint_meta) >= collector.max_endpoints_per_org):
                        continue
                    endpoint_meta[url] = (
                        cand.apex, cand.confidence, host, src, o.get("seen", ""))
                elif src == "urlscan" and prev[3] != "urlscan":
                    endpoint_meta[url] = (
                        prev[0], prev[1], prev[2], "urlscan", o.get("seen", ""))

        # Wayback (past) + urlscan.io (recent) — different failure modes, so both
        # widen coverage; urlscan also tells us what is current. Best-effort each.
        # Limits come from config so max_endpoints_per_org is actually reachable.
        stop = False
        for name, fetch, limit in (
            ("wayback", wayback.fetch_observations, collector.wayback_limit),
            ("urlscan", urlscan.fetch_observations, collector.urlscan_limit),
        ):
            if limit <= 0:
                continue
            try:
                _ingest(fetch(http, cand.apex, limit), name)
            except RequestBudgetExceeded as exc:
                problems.append(f"[{org.org_id}] stopped at request cap: {exc}")
                stop = True
                break
            except Exception as exc:  # noqa: BLE001
                problems.append(f"[{org.org_id}] {name} {cand.apex}: {exc}")
        if stop:
            break

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
        asn_map = cymru.annotate(unique_ips)

    date = run_date()
    prefix = _prefix(org.org_id)
    at = timestamp_now()
    assets: list[Asset] = []

    def _add(
        asset_type: str, apex: str, conf: str, host: str, url: str = "",
        *, source: str, freshness: str, last_seen: str = "",
    ) -> None:
        ip = ip_map.get(host, "")
        assets.append(
            Asset(
                record_id=f"{prefix}_{date}_{len(assets) + 1:06d}",
                org_id=org.org_id,
                org_name=org.name,
                apex=apex,
                apex_confidence=conf,  # type: ignore[arg-type]
                asset_type=asset_type,  # type: ignore[arg-type]
                host=host,
                source=source,
                discovered_at=at,
                url=url,
                resolved_ip=ip,
                asn=asn_map.get(ip, ""),
                freshness=freshness,
                last_seen=last_seen,
            )
        )

    # Hosts: resolving now = current, otherwise a name with no live address.
    for host in sorted(host_apex):
        apex, conf = host_apex[host]
        fresh = "current" if ip_map.get(host) else "archived"
        _add("apex" if host == apex else "subdomain", apex, conf, host,
             source="crt.sh+wayback", freshness=fresh)
    # Endpoints: urlscan saw it recently = current; wayback-only = archived.
    for url, (apex, conf, host, ep_src, seen) in endpoint_meta.items():
        fresh = "current" if ep_src == "urlscan" else "archived"
        _add("endpoint", apex, conf, host, url,
             source=ep_src, freshness=fresh, last_seen=seen)

    if not assets:
        problems.append(f"[{org.org_id}] no assets collected")
    say(f"[{org.org_id}] done: {len(assets)} assets")
    return assets, problems
