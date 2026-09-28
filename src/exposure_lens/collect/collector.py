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
from ..core.net import Http, NetworkDown, RequestBudgetExceeded
from ..core.progress import OrgProgress
from ..sources import crtsh, cymru, urlscan, wayback
from .resolve import resolve_hosts

_ID_SANITIZE = re.compile(r"[^A-Z0-9]+")
TARGET_CONFIDENCES = ("high", "medium")
# With at least this many hosts, zero resolving means our DNS was down.
RESOLVE_SANITY_HOSTS = 5

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


def _ingest(
    state: OrgProgress, collector: CollectorConfig, cand: ApexCandidate,
    obs: list[dict], src: str,
) -> None:
    """Fold observed URLs into ``state``: their hosts, and non-static endpoints."""
    for o in obs:
        url = o["url"]
        host = (urlsplit(url).hostname or "").lower()
        if not host or not _in_scope(host, cand.apex):
            continue
        state.host_apex.setdefault(host, [cand.apex, cand.confidence])
        if not _is_endpoint(url):
            continue
        prev = state.endpoint_meta.get(url)
        # urlscan (present-tense) upgrades a wayback-only entry; keep the more
        # recent last_seen.
        if prev is None:
            # max_endpoints_per_org 0 = 무제한
            if (collector.max_endpoints_per_org
                    and len(state.endpoint_meta) >= collector.max_endpoints_per_org):
                continue
            state.endpoint_meta[url] = [
                cand.apex, cand.confidence, host, src, o.get("seen", "")]
        elif src == "urlscan" and prev[3] != "urlscan":
            state.endpoint_meta[url] = [
                prev[0], prev[1], prev[2], "urlscan", o.get("seen", "")]


def _split_hosts(
    state: OrgProgress, collector: CollectorConfig, cand: ApexCandidate,
    apex_urls: list[str], *, resolve: bool,
) -> tuple[list[str], int]:
    """Hosts of this apex to re-query one by one, and how many the cap left out.

    Hosts the apex-wide answer already covered in full are skipped. CDX sorts by
    host, so every host in that answer is complete except the last one, which
    the limit may have cut mid-way. Only hosts that resolve now are kept (a dead
    host is no probe target, so its old paths are low value) unless resolution
    is off, in which case liveness is unknown and all are kept.
    """
    seen = [(urlsplit(u).hostname or "").lower() for u in apex_urls]
    covered = set(seen[:-1]) - {seen[-1]} if seen else set()
    hosts = sorted(
        (h for h, (apex, _conf) in state.host_apex.items()
         if apex == cand.apex and h not in covered),
        key=lambda h: (len(h), h),  # apex-most first when the cap bites
    )
    if resolve and hosts:
        ips = resolve_hosts(
            hosts, timeout=collector.resolve_timeout, workers=collector.resolve_workers,
        )
        hosts = [h for h in hosts if ips.get(h)]
    cap = collector.max_wayback_split_hosts
    if cap and len(hosts) > cap:
        return hosts[:cap], len(hosts) - cap
    return hosts, 0


def _collect_wayback(
    http: Http,
    org: OrgConfig,
    collector: CollectorConfig,
    cand: ApexCandidate,
    state: OrgProgress,
    *,
    resolve: bool,
    log: Callable[[str], None],
) -> None:
    """Wayback endpoints for one apex, splitting per host when one query can't.

    One ``*.apex`` query is cheap and enough for most apexes. When it comes
    back full (``wayback_limit`` rows) it holds only the alphabetically-first
    hosts; when it fails, typically a wildcard too big for CDX to answer in
    time, it holds nothing. Either way the apex's live hosts are then queried
    one by one, bounded by ``max_wayback_split_hosts``.
    """
    limit = collector.wayback_limit
    try:
        urls = wayback.fetch_urls(http, cand.apex, limit)
        failed = ""
    except (RequestBudgetExceeded, NetworkDown):
        raise
    except Exception as exc:  # noqa: BLE001
        urls, failed = [], str(exc)
    _ingest(state, collector, cand, wayback.as_observations(urls), "wayback")

    truncated = len(urls) >= limit
    if not (truncated or failed) or not collector.wayback_split:
        if failed:
            state.problems.append(f"[{org.org_id}] wayback {cand.apex}: {failed}")
        return

    why = f"{limit}건 상한 도달" if truncated else f"조회 실패({failed})"
    hosts, skipped = _split_hosts(state, collector, cand, urls, resolve=resolve)
    log(f"[{org.org_id}]   wayback {cand.apex}: {why} → 호스트 {len(hosts)}개 개별 조회")
    errors = 0
    for i, host in enumerate(hosts, 1):
        try:
            got = wayback.fetch_host_urls(http, host, limit)
        except (RequestBudgetExceeded, NetworkDown):
            raise
        except Exception:  # noqa: BLE001 - one host failing is not fatal
            errors += 1
            continue
        _ingest(state, collector, cand, wayback.as_observations(got), "wayback")
        if i % 50 == 0:
            log(f"[{org.org_id}]   wayback 호스트별 {i}/{len(hosts)}")

    note = f"[{org.org_id}] wayback {cand.apex}: {why} → 호스트 {len(hosts)}개 개별 조회"
    if errors:
        note += f", {errors}개 실패"
    if skipped:
        note += f", {skipped}개는 max_wayback_split_hosts 초과로 생략"
    state.problems.append(note)


def _collect_apex(
    http: Http,
    org: OrgConfig,
    collector: CollectorConfig,
    cand: ApexCandidate,
    state: OrgProgress,
    *,
    endpoints: bool,
    resolve: bool = True,
    log: Callable[[str], None] | None = None,
) -> None:
    """crt.sh hosts, then Wayback/urlscan endpoints, for one apex into ``state``.

    A single source failing is recorded and the others still run; only the
    request cap and a dead network abort the apex (leaving it unfinished).
    crt.sh runs first so a Wayback split knows the apex's hosts.
    """
    try:
        for host in crtsh.domain_search(http, cand.apex):
            state.host_apex.setdefault(host, [cand.apex, cand.confidence])
    except (RequestBudgetExceeded, NetworkDown):
        raise
    except Exception as exc:  # noqa: BLE001 - report source failures in summary
        state.problems.append(f"[{org.org_id}] crt.sh %.{cand.apex}: {exc}")

    if not endpoints:
        return
    # urlscan (recent) first: its hosts also feed the Wayback split.
    if collector.urlscan_limit > 0:
        try:
            obs = urlscan.fetch_observations(http, cand.apex, collector.urlscan_limit)
            _ingest(state, collector, cand, obs, "urlscan")
        except (RequestBudgetExceeded, NetworkDown):
            raise
        except Exception as exc:  # noqa: BLE001
            state.problems.append(f"[{org.org_id}] urlscan {cand.apex}: {exc}")
    if collector.wayback_limit > 0:
        _collect_wayback(
            http, org, collector, cand, state,
            resolve=resolve, log=log or (lambda _: None),
        )


def _finish(
    state: OrgProgress, org: OrgConfig, problems: list[str], cut: list[str]
) -> list[str]:
    """Settle ``state.complete`` and return the org's full problem list."""
    state.complete = not cut
    problems = [*problems, *state.problems]
    if cut:
        problems.append(
            f"[{org.org_id}] 연결 실패로 미완료: {', '.join(cut)} (--resume 으로 재수집)"
        )
    return problems


def collect_org(
    http: Http,
    org: OrgConfig,
    collector: CollectorConfig,
    *,
    resolve: bool = True,
    endpoints: bool = True,
    log: Callable[[str], None] | None = None,
    progress: OrgProgress | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[list[Asset], list[str]]:
    """Return (assets, problems) for one organization.

    ``progress`` carries what an interrupted run already did for this org (its
    apex candidates and finished apexes); those steps are skipped, not redone.
    ``checkpoint`` is called after discovery and after every apex so the caller
    can persist ``progress``. A step during which a request failed to connect
    is not marked done (``progress.complete`` stays False), and a
    ``NetworkDown`` propagates; either way a resume redoes that step.
    """
    say = log or (lambda _: None)
    state = progress or OrgProgress(org_id=org.org_id)
    save = checkpoint or (lambda: None)
    cut: list[str] = []  # steps the connection cut off; redone on resume

    if state.candidates:
        candidates = [
            ApexCandidate(**{**c, "evidence": tuple(c.get("evidence", ()))})
            for c in state.candidates
        ]
        say(f"[{org.org_id}] resuming: {len(state.done_apexes)} apexes already done")
    else:
        say(f"[{org.org_id}] discovering apex...")
        before = http.connect_failure_total
        candidates, errors = discover_apex(http, org)
        state.discovery_errors = [f"[{org.org_id}] {e}" for e in errors]
        if http.connect_failure_total == before:
            state.candidates = [c.to_dict() for c in candidates]
            save()
        else:  # a search cut off by the link is redone, not cached
            cut.append("apex discovery")
    problems = list(state.discovery_errors)
    if not candidates:
        problems.append(f"[{org.org_id}] no apex candidates")
        return [], _finish(state, org, problems, cut)

    targets = select_target_apexes(candidates, collector.max_apex_per_org)
    say(f"[{org.org_id}] apex: {len(candidates)} candidates, {len(targets)} to collect")
    eligible = sum(1 for c in candidates if c.confidence in TARGET_CONFIDENCES)
    if eligible > len(targets):
        problems.append(
            f"[{org.org_id}] capped apexes {len(targets)}/{eligible} (max_apex_per_org)"
        )

    # host -> [apex, confidence]; first apex to claim a host wins.
    host_apex = state.host_apex
    # url -> [apex, conf, host, endpoint_source, last_seen]
    endpoint_meta = state.endpoint_meta
    done = set(state.done_apexes)

    for i, cand in enumerate(targets, 1):
        if cand.apex in done:
            continue
        say(f"[{org.org_id}] ({i}/{len(targets)}) {cand.apex} crt.sh/wayback...")
        before = http.connect_failure_total
        try:
            _collect_apex(
                http, org, collector, cand, state,
                endpoints=endpoints, resolve=resolve, log=say,
            )
        except RequestBudgetExceeded as exc:
            problems.append(f"[{org.org_id}] stopped at request cap: {exc}")
            break
        if http.connect_failure_total != before:
            cut.append(cand.apex)  # keep what it got, but redo it on resume
            continue
        state.done_apexes.append(cand.apex)
        save()

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
        # Not one of several hosts resolving is what a dropped link looks like
        # (a real org always has something live); it would mark every host
        # "archived", so the org is left for resume instead.
        if len(host_apex) >= RESOLVE_SANITY_HOSTS and not unique_ips:
            cut.append("DNS resolve")
        say(f"[{org.org_id}] ASN lookup for {len(unique_ips)} IPs...")
        asn_map = cymru.annotate(unique_ips)

    problems = _finish(state, org, problems, cut)
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
