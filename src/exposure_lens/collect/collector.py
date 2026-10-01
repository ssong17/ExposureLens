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
from ..sources import search as search_src
from .resolve import resolve_hosts

_ID_SANITIZE = re.compile(r"[^A-Z0-9]+")
# A label that opens with a phone-number-shaped run (two-plus digits, then two
# or more hyphen-digit groups) is scraped junk — e.g. "031-478-7879www" glued
# from a `tel:` link, which a wildcard DNS then happily resolves. Real labels
# like "24-7" (one group) or "3-com" (one digit) are left alone.
_PHONE_LABEL = re.compile(r"^\d{2,}(?:-\d+){2,}")
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
    if not all(0 < len(lbl) <= 63 for lbl in labels):
        return False
    return not any(_PHONE_LABEL.match(lbl) for lbl in labels)


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
    return targets[:limit] if limit else targets  # limit 0 = unlimited


_NUM_SEG = re.compile(r"/\d+(?=/|$)")


def _variant_key(host: str, url: str) -> tuple[str, str]:
    """Bucket a URL into its "template": (host, path with query + numeric ids
    stripped).

    Two families collapse to one bucket, because neither changes the exposure
    shape — only the content:
    - query variants: ``/board.php?idx=1``, ``?idx=2``, ``?page=9`` (ignored)
    - numeric path ids: ``/news/pr/1``, ``/news/pr/2`` … ``/board/view/1837``
      → ``/news/pr/N``, ``/board/view/N`` (every article is the same template)

    So ``max_endpoint_variants_per_path`` keeps only a few representatives per
    template instead of every board post, which is what balloons collect and
    the later body reads.
    """
    path = _NUM_SEG.sub("/N", urlsplit(url).path)
    return host, path


def _ingest(
    state: OrgProgress, collector: CollectorConfig, cand: ApexCandidate,
    obs: list[dict], src: str, variant_counts: dict[tuple[str, str], int],
) -> None:
    """Fold observed URLs into ``state``: their hosts, and non-static endpoints.

    ``variant_counts`` caps how many query-string variants of one (host, path)
    are stored (``max_endpoint_variants_per_path``); the rest are dropped here.
    """
    cap = collector.max_endpoint_variants_per_path
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
            # max_endpoints_per_org 0 = unlimited
            if (collector.max_endpoints_per_org
                    and len(state.endpoint_meta) >= collector.max_endpoints_per_org):
                continue
            # Cap query-string variants of the same page (0 = unlimited).
            vkey = _variant_key(host, url)
            if cap and variant_counts.get(vkey, 0) >= cap:
                continue
            variant_counts[vkey] = variant_counts.get(vkey, 0) + 1
            state.endpoint_meta[url] = [
                cand.apex, cand.confidence, host, src, o.get("seen", "")]
        elif src == "urlscan" and prev[3] != "urlscan":
            state.endpoint_meta[url] = [
                prev[0], prev[1], prev[2], "urlscan", o.get("seen", "")]


def _collect_wayback(
    http: Http,
    org: OrgConfig,
    collector: CollectorConfig,
    cand: ApexCandidate,
    state: OrgProgress,
    variant_counts: dict[tuple[str, str], int],
    *,
    log: Callable[[str], None],
) -> bool:
    """Wayback endpoints for one apex via CDX pagination.

    One paginated ``*.apex`` sweep returns every subdomain's URLs (no 1000-row
    cap gap) in a handful of requests — ``wayback.fetch_urls`` walks the pages.
    ``wayback_max_pages`` bounds a pathologically large domain.

    Returns True when the apex's endpoints were LOST to a source outage (the
    query raised), so the caller leaves the apex unfinished for ``--resume``.
    """
    try:
        urls = wayback.fetch_urls(http, cand.apex, collector.wayback_max_pages)
        failed = ""
    except (RequestBudgetExceeded, NetworkDown):
        raise
    except Exception as exc:  # noqa: BLE001
        urls, failed = [], str(exc)
    _ingest(state, collector, cand, wayback.as_observations(urls), "wayback", variant_counts)
    if failed:
        state.problems.append(f"[{org.org_id}] wayback {cand.apex}: {failed}")
        return True  # outage -> redo on resume
    log(f"[{org.org_id}]   wayback {cand.apex}: {len(urls)} URLs (paginated)")
    return False


def _collect_apex(
    http: Http,
    org: OrgConfig,
    collector: CollectorConfig,
    cand: ApexCandidate,
    state: OrgProgress,
    variant_counts: dict[tuple[str, str], int] | None = None,
    *,
    endpoints: bool,
    search: bool = False,
    search_queries: tuple[str, ...] = (),
    log: Callable[[str], None] | None = None,
) -> bool:
    """crt.sh hosts, then urlscan/search/Wayback endpoints, for one apex.

    A single source failing is recorded and the others still run; only the
    request cap and a dead network abort the apex (leaving it unfinished).

    Returns True when the apex's endpoint data was lost to a source outage (see
    ``_collect_wayback``), so the caller can leave the apex for ``--resume``.
    """
    if variant_counts is None:
        variant_counts = {}
    try:
        for host in crtsh.domain_search(http, cand.apex):
            state.host_apex.setdefault(host, [cand.apex, cand.confidence])
    except (RequestBudgetExceeded, NetworkDown):
        raise
    except Exception as exc:  # noqa: BLE001 - report source failures in summary
        state.problems.append(f"[{org.org_id}] crt.sh %.{cand.apex}: {exc}")

    if not endpoints:
        return False
    # urlscan (recent) first: its hosts also feed the Wayback split.
    if collector.urlscan_limit > 0:
        try:
            obs = urlscan.fetch_observations(http, cand.apex, collector.urlscan_limit)
            _ingest(state, collector, cand, obs, "urlscan", variant_counts)
        except (RequestBudgetExceeded, NetworkDown):
            raise
        except Exception as exc:  # noqa: BLE001
            state.problems.append(f"[{org.org_id}] urlscan {cand.apex}: {exc}")
    # Search-engine discovery (opt-in): URLs indexed by a search engine but not
    # in the archive/CT — admin/CMS pages Wayback misses. No-op without an API
    # key (see sources.search).
    if search and collector.search_limit > 0:
        try:
            obs = search_src.fetch_observations(
                http, cand.apex, collector.search_limit,
                queries=search_queries or collector.search_queries,
            )
            _ingest(state, collector, cand, obs, "search", variant_counts)
        except (RequestBudgetExceeded, NetworkDown):
            raise
        except Exception as exc:  # noqa: BLE001
            state.problems.append(f"[{org.org_id}] search {cand.apex}: {exc}")
    return _collect_wayback(
        http, org, collector, cand, state, variant_counts,
        log=log or (lambda _: None),
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
    search: bool = False,
    search_queries: tuple[str, ...] = (),
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
    # (host, path) -> stored variant count, rebuilt from what resume loaded so
    # the per-page cap holds across a resumed run too.
    variant_counts: dict[tuple[str, str], int] = {}
    for url, meta in endpoint_meta.items():
        variant_counts[_variant_key(meta[2], url)] = (
            variant_counts.get(_variant_key(meta[2], url), 0) + 1
        )

    for i, cand in enumerate(targets, 1):
        if cand.apex in done:
            continue
        say(f"[{org.org_id}] ({i}/{len(targets)}) {cand.apex} crt.sh/wayback...")
        before = http.connect_failure_total
        try:
            lost = _collect_apex(
                http, org, collector, cand, state, variant_counts,
                endpoints=endpoints, search=search,
                search_queries=search_queries, log=say,
            )
        except RequestBudgetExceeded as exc:
            problems.append(f"[{org.org_id}] stopped at request cap: {exc}")
            break
        # Leave the apex for resume when the link dropped mid-way OR a source
        # outage lost its endpoints (503/timeout is not a connect failure, so
        # it does not show up in connect_failure_total — hence the second test).
        if http.connect_failure_total != before or lost:
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
        fresh = "current" if ep_src in ("urlscan", "search") else "archived"
        _add("endpoint", apex, conf, host, url,
             source=ep_src, freshness=fresh, last_seen=seen)

    if not assets:
        problems.append(f"[{org.org_id}] no assets collected")
    say(f"[{org.org_id}] done: {len(assets)} assets")
    return assets, problems
