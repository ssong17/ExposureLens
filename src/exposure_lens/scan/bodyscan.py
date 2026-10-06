"""Response-body reading engine, shared by the two body passes.

Reading what an address *serves* (not just its URL/host name) is the job of two
stages:

  - ``scan``: reads ARCHIVED snapshots from the Wayback Machine. The target is
    never contacted. ``scan_archive_bodies`` is this stage's entry point, and it
    is resumable (see ``done``/``on_result``).
  - ``probe``: reads the LIVE body with one GET to the target. The ``probe``
    package drives this via ``read_bodies(..., source=FETCH)``.

The low-level loop (``read_bodies``) is the same for both — select endpoints,
retrieve each body, run the content rules, follow a source map — so the two
stages cannot drift apart. The engine lives in ``scan`` because the scan stage
owns it and ``probe`` only reuses the fetch side (``scan`` never imports
``probe``, keeping the scan→probe dependency one-way).

It never guesses new paths and never sends a payload. Matched values are stored
verbatim (unmasked) by ``scan_body``.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import replace
from typing import Callable
from urllib.parse import urljoin, urlsplit

from ..core.models import (
    SEVERITY_ORDER,
    Finding,
    FindingIds,
    confidence_rank,
    timestamp_now,
)
from ..core.net import Http, RequestBudgetExceeded
from ..sources import body as body_src
from .rules import AUTHZ_PATH
from .scanner import scan_body

WAYBACK = "wayback"
FETCH = "fetch"

_SOURCEMAP_REF = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

# Client-code endpoints worth reading for the JS/authz/surface rules — the
# script bundles and source maps where routes and auth checks actually live.
_SCRIPT_EXT = {"js", "mjs", "cjs", "ts", "json", "map"}

# Static assets: a 2xx on one of these is the server returning a file, never a
# gate falling open. ``authz-open`` is about a protected PAGE answering, so a
# .js/.css/.map named ".../internal/foo.js" must not count as broken access.
_STATIC_ASSET_EXT = {
    "js", "mjs", "cjs", "css", "map", "json", "ico", "svg", "png", "jpg",
    "jpeg", "gif", "webp", "woff", "woff2", "ttf", "eot", "otf",
}

# A 200 page that shows a login form means authentication IS enforced — the
# gate is working, so it must NOT be reported as "open without auth".
_LOGIN_MARKERS = re.compile(
    r"""(?ix)
    type\s*=\s*["']password["']      # a password input
    | name\s*=\s*["']password["']
    | \b(로그인|로그인하기|login|log\s*in|sign\s*in|signin)\b
    | \bauthenticat
    """,
)

# Keep at most this many query-string variants of one (host, path). The 455
# `?page=1..N` copies of one template all serve the same body, so probing every
# one cost ~4h and (before dedup) reported the same secret hundreds of times. A
# few variants still cover the case where the query genuinely changes the body.
_MAX_VARIANTS_PER_PATH = 3


def _sourcemap_sources(map_text: str) -> list[str]:
    """Original source strings from a source map (empty if it carries none)."""
    try:
        data = json.loads(map_text)
    except (json.JSONDecodeError, ValueError):
        return []
    contents = data.get("sourcesContent")
    if isinstance(contents, list):
        return [c for c in contents if isinstance(c, str) and c]
    return []


def _read_sourcemap(
    fetch_fn: "Callable[[Http, str], tuple[int, str]]",
    http: Http,
    js_url: str,
    js_text: str,
) -> tuple[str, list[str]]:
    """Resolve a JS body's source map and return (map_url, original sources).

    Handles inline (data: base64) maps without a request; otherwise fetches the
    .map next to the .js via the same source (archive or direct). Recall move:
    minified bundles hide routes/authz, but the map restores the real source.
    """
    m = _SOURCEMAP_REF.search(js_text)
    if not m:
        return "", []
    ref = m.group(1).strip()
    if ref.startswith("data:"):
        _, _, b64 = ref.partition("base64,")
        try:
            decoded = base64.b64decode(b64).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return "", []
        return js_url, _sourcemap_sources(decoded)
    map_url = urljoin(js_url, ref)
    _status, map_text = fetch_fn(http, map_url)
    return map_url, _sourcemap_sources(map_text) if map_text else []


def _is_script_like(url: str) -> bool:
    path = urlsplit(url).path
    tail = path.rsplit("/", 1)[-1]
    ext = tail.rsplit(".", 1)[-1].lower() if "." in tail else ""
    return ext in _SCRIPT_EXT


def _is_static_asset(url: str) -> bool:
    tail = urlsplit(url).path.rsplit("/", 1)[-1]
    ext = tail.rsplit(".", 1)[-1].lower() if "." in tail else ""
    return ext in _STATIC_ASSET_EXT


def _looks_like_login(text: str) -> bool:
    return bool(_LOGIN_MARKERS.search(text[:20000]))


def _looks_like(length: int, catch_all_length: int) -> bool:
    """True when a body is close enough to the host's catch-all page to be it.

    Exact-match SPAs serve byte-identical index.html for every path; soft-404
    pages vary a little, so allow a small tolerance.
    """
    if catch_all_length == 0:
        return length == 0
    return abs(length - catch_all_length) <= max(64, catch_all_length // 20)


def _select_targets(
    assets: list[dict],
    finding_urls: set[str] | None,
    max_confidence_rank: int,
    scripts_only: bool = False,
) -> list[dict]:
    targets: list[dict] = []
    seen: set[str] = set()
    variants: dict[tuple[str, str], int] = {}
    for asset in assets:
        if asset.get("asset_type") != "endpoint":
            continue
        url = asset.get("url", "")
        if not url or url in seen:
            continue
        if confidence_rank(asset.get("apex_confidence", "low")) > max_confidence_rank:
            continue
        if finding_urls is not None and url not in finding_urls:
            continue
        if scripts_only and not _is_script_like(url):
            continue
        # Collapse query-string variants of one path (unless an explicit finding
        # URL list already pinned exactly which URLs to read).
        if finding_urls is None:
            parts = urlsplit(url)
            vkey = (parts.hostname or "", parts.path)
            n = variants.get(vkey, 0)
            if n >= _MAX_VARIANTS_PER_PATH:
                continue
            variants[vkey] = n + 1
        seen.add(url)
        targets.append(asset)
    return targets


def _authz_finding(asset: dict, url: str, status: int, next_id) -> Finding:
    return Finding(
        finding_id=next_id(),
        org_id=asset.get("org_id", ""),
        asset_ref=asset.get("record_id", ""),
        org_name=asset.get("org_name", ""),
        severity="high",
        category="access-control",
        rule="authz-open",
        host=asset.get("host", ""),
        url=url,
        evidence=f"{status} unauthenticated on protected path",
        discovered_at=timestamp_now(),
        path=urlsplit(url).path or "/",
        status=str(status),
        source="fetch-status",
        freshness="current",  # the 2xx we just received proves it
    )


def read_bodies(
    http: Http,
    assets: list[dict],
    *,
    source: str = WAYBACK,
    min_severity: str = "medium",
    finding_urls: set[str] | None = None,
    max_targets: int = 0,  # 0 = unlimited
    scripts_only: bool = False,
    next_id: "Callable[[], str] | None" = None,
    dedup: "dict[tuple[str, str, str], int] | None" = None,
    missed_out: "list[str] | None" = None,
    vibe: bool = False,
    log: Callable[[str], None] | None = None,
    done: "dict[str, list[dict]] | None" = None,
    done_missed: "set[str] | None" = None,
    on_result: "Callable[[str, list[dict], bool], None] | None" = None,
) -> tuple[list[Finding], list[str]]:
    """Retrieve each endpoint body and run the content rules over it.

    ``source`` is WAYBACK (archived snapshot; the ``scan`` stage) or FETCH (one
    live GET; the ``probe`` stage). ``dedup`` (see ``scan_body``) collapses one
    templated secret across pages. ``missed_out``: on a WAYBACK pass, endpoint
    URLs the archive had no snapshot for are appended here, so the probe stage
    can fetch just those live (the "catch what scan missed" half of the flow).

    Resume (WAYBACK only): ``done`` maps an already-processed archive URL to the
    finding dicts it produced; such URLs are replayed (findings rebuilt with
    fresh ids, miss re-recorded) instead of re-fetched. ``on_result`` is called
    after each freshly fetched WAYBACK URL with ``(url, finding_dicts, missed)``
    so the caller can persist it for the next resume.
    """
    say = log or (lambda _: None)
    next_id = next_id or FindingIds("A")
    done = done or {}
    done_missed = done_missed or set()
    problems: list[str] = []

    # Direct fetch touches the target, so restrict it to high-confidence apexes;
    # archived reads never touch the target and may include medium.
    max_conf_rank = confidence_rank("high" if source == FETCH else "medium")
    targets = _select_targets(assets, finding_urls, max_conf_rank, scripts_only)
    if max_targets and len(targets) > max_targets:
        problems.append(f"capped targets {max_targets}/{len(targets)}")
        targets = targets[:max_targets]

    body_source = "fetch-body" if source == FETCH else "wayback-body"
    findings: list[Finding] = []
    # host -> homepage body length (-1 if "/" did not answer 2xx). An SPA/catch-
    # all serves the same index for every route, so a discovered path whose body
    # matches the homepage is the index fallback, not that path's content. "/"
    # is a real path, so this keeps the "never guess paths" guarantee. Computed
    # once per host on the FETCH pass.
    home_len: dict[str, int] = {}
    say(f"reading {len(targets)} endpoint bodies via {source}...")

    for i, asset in enumerate(targets, 1):
        url = asset["url"]

        # Resume: this archive URL was already processed in an interrupted run.
        # Replay its findings (with fresh ids) and miss; do not re-fetch.
        if source == WAYBACK and url in done:
            for d in done[url]:
                f = Finding(**{**d, "finding_id": next_id()})
                findings.append(f)
                if dedup is not None:
                    dedup.setdefault((f.org_id, f.rule, f.evidence), 1)
            if url in done_missed and missed_out is not None:
                missed_out.append(url)
            say(f"  ({i}/{len(targets)}) reused {url}")
            continue

        try:
            if source == FETCH:
                status, text = body_src.fetch_body(http, url)
            else:
                status, text = body_src.wayback_body(http, url)
        except RequestBudgetExceeded as exc:
            problems.append(f"stopped at request cap: {exc}")
            break
        say(f"  ({i}/{len(targets)}) {status or '-'} {url}")

        url_findings: list[Finding] = []

        # Archive had no usable snapshot for this URL: note it so a later probe
        # pass can fetch it live (the scan stage could not see it).
        missed = source == WAYBACK and not text
        if missed and missed_out is not None:
            missed_out.append(url)

        # Did this 2xx really serve THIS path's content? On an SPA/catch-all the
        # homepage is returned for every route, so an archived path that now just
        # renders the index is not a current hit. Compare the body to the host
        # root ("/"); a match means it is the index fallback (soft-404).
        trust_2xx = True
        path = urlsplit(url).path or "/"
        if source == FETCH and 200 <= status < 300 and path != "/":
            host = urlsplit(url).hostname or ""
            if host not in home_len:
                try:
                    hstatus, hlen = body_src.home_body(http, url)
                except RequestBudgetExceeded as exc:
                    problems.append(f"stopped at request cap: {exc}")
                    break
                home_len[host] = hlen if 200 <= hstatus < 300 else -1
            if home_len[host] >= 0 and _looks_like(len(text), home_len[host]):
                trust_2xx = False  # just the host's index page, not this path

        # A direct fetch always yields a liveness signal; record it even when the
        # body is clean so the report can rank live exposures above stale ones.
        if source == FETCH:
            from ..probe.verify import make_liveness_finding
            url_findings.append(
                make_liveness_finding(asset, url, status, next_id,
                                      source="fetch-status")
            )

        # Authorization gap: a should-be-protected path that answers 2xx with its
        # REAL content and no auth. Excluded: static assets (a .js answering 200
        # is not broken access control), the index fallback (not real content),
        # and a login/challenge PAGE (200 showing a login form means auth IS
        # enforced — that is the gate working, not an open door).
        if (source == FETCH and trust_2xx and 200 <= status < 300
                and not _is_static_asset(url) and AUTHZ_PATH.search(url)
                and not _looks_like_login(text)):
            url_findings.append(_authz_finding(asset, url, status, next_id))

        # A soft-404 / index-fallback body is not this URL's content, so running
        # secret/content rules on it only re-finds the homepage. Skip.
        if text and not (source == FETCH and not trust_2xx):
            # A body we just fetched is served now; an archived snapshot is not.
            body_freshness = "current" if source == FETCH else "archived"
            url_findings.extend(
                scan_body(
                    text,
                    asset=asset,
                    url=url,
                    status=str(status) if status else "",
                    source=body_source,
                    min_severity=min_severity,
                    next_id=next_id,
                    freshness=body_freshness,
                    dedup=dedup,
                    vibe=vibe,
                )
            )

            # Follow a source map: minified bundles hide routes/authz from the
            # rules, but the map's original sources restore them.
            if "sourceMappingURL" in text:
                fetch_fn = (
                    body_src.fetch_body if source == FETCH else body_src.wayback_body
                )
                try:
                    map_url, sources = _read_sourcemap(fetch_fn, http, url, text)
                except RequestBudgetExceeded as exc:
                    problems.append(f"stopped at request cap: {exc}")
                    break
                if sources:
                    say(f"      sourcemap: {len(sources)} sources <- {map_url}")
                    url_findings.extend(
                        scan_body(
                            "\n".join(sources),
                            asset=asset,
                            url=map_url or url,
                            status="",
                            source=f"{body_source}-sourcemap",
                            min_severity=min_severity,
                            next_id=next_id,
                            freshness=body_freshness,
                            dedup=dedup,
                            vibe=vibe,
                        )
                    )

        findings.extend(url_findings)
        # Persist this archive URL's result so a resume can skip it.
        if source == WAYBACK and on_result is not None:
            on_result(url, [f.to_dict() for f in url_findings], missed)

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    say(f"done: {len(findings)} findings from {len(targets)} endpoints")
    return findings, problems


def annotate_duplicates(
    rows: list[Finding], dedup: dict[tuple[str, str, str], int]
) -> list[Finding]:
    """Append '(+N pages)' to a finding whose secret recurred on other pages."""
    out: list[Finding] = []
    for f in rows:
        extra = dedup.get((f.org_id, f.rule, f.evidence), 1) - 1
        if extra > 0:
            f = replace(f, evidence=f"{f.evidence} (+{extra} pages)")
        out.append(f)
    return out


def scan_archive_bodies(
    http: Http,
    assets: list[dict],
    *,
    min_severity: str = "medium",
    next_id: "Callable[[], str] | None" = None,
    vibe: bool = False,
    log: Callable[[str], None] | None = None,
    done: "dict[str, list[dict]] | None" = None,
    done_missed: "set[str] | None" = None,
    on_result: "Callable[[str, list[dict], bool], None] | None" = None,
) -> tuple[list[Finding], list[str], list[str]]:
    """Archived-body pass for the ``scan`` stage.

    Reads ARCHIVED snapshots (Wayback) — never the target — to pull
    secrets/backend-config/Supabase/Firebase that URL/host/port rules cannot
    see. The confidence floor is fixed at ``medium`` (handled by ``read_bodies``,
    which caps a non-FETCH pass at medium).

    Returns ``(findings, missed, problems)``: ``missed`` is the endpoint URLs
    the archive had no snapshot for, so the ``probe`` stage can fetch just those.
    ``done``/``on_result`` make the pass resumable (see ``read_bodies``).
    """
    next_id = next_id or FindingIds("A")
    dedup: dict[tuple[str, str, str], int] = {}
    missed: list[str] = []
    findings, problems = read_bodies(
        http, assets, source=WAYBACK, min_severity=min_severity,
        next_id=next_id, dedup=dedup, missed_out=missed, vibe=vibe, log=log,
        done=done, done_missed=done_missed, on_result=on_result,
    )
    findings = annotate_duplicates(findings, dedup)
    suppressed = sum(n - 1 for n in dedup.values() if n > 1)
    if suppressed:
        problems.append(
            f"같은 시크릿이 여러 페이지에 반복돼 {suppressed}건을 합쳤습니다 "
            f"(finding당 '(+N pages)'로 표시)"
        )
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings, missed, problems
