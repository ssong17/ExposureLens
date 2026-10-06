"""Passive archived-body reader for the ``scan`` stage, plus the body helpers
the active ``probe`` loop reuses.

Reading what an address *serves* (not just its URL/host name) happens in two
places, which deliberately do NOT share one loop (their request models differ):

  - ``scan`` (here): reads ARCHIVED snapshots from the Wayback Machine, never
    contacting the target. ``read_bodies`` / ``scan_archive_bodies`` is the
    entry point, and it is resumable (see ``done``/``on_result``).
  - ``probe`` (``probe.prober``): reads the LIVE body with one GET to the target,
    and additionally checks reachability / known-exposure paths / unauth access.

What the two share — endpoint selection (``_select_targets``), running the
content rules over a body and following its source map (``scan_served_body``),
the SPA/login guards — lives here so both call the one copy; ``scan`` never
imports ``probe``, keeping the scan→probe dependency one-way.

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
)
from ..core.net import Http, RequestBudgetExceeded
from ..sources import body as body_src
from .scanner import scan_body

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


def scan_served_body(
    http: Http,
    *,
    asset: dict,
    url: str,
    text: str,
    source: str,
    status: str,
    freshness: str,
    min_severity: str,
    next_id,
    dedup: "dict[tuple[str, str, str], int] | None",
    vibe: bool,
    fetch_fn: "Callable[[Http, str], tuple[int, str]]",
    log: Callable[[str], None] | None = None,
) -> list[Finding]:
    """Run the content rules over one already-retrieved body, then follow its
    source map (if any) and scan the restored sources too.

    Shared by the ``scan`` archive reader and the ``probe`` live loop so the two
    cannot drift. ``fetch_fn`` retrieves the .map via the same transport the body
    came from (archived or live). ``RequestBudgetExceeded`` from the .map fetch
    propagates to the caller.
    """
    say = log or (lambda _: None)
    findings = list(scan_body(
        text, asset=asset, url=url, status=status, source=source,
        min_severity=min_severity, next_id=next_id, freshness=freshness,
        dedup=dedup, vibe=vibe,
    ))
    if "sourceMappingURL" in text:
        map_url, sources = _read_sourcemap(fetch_fn, http, url, text)
        if sources:
            say(f"      sourcemap: {len(sources)} sources <- {map_url}")
            findings.extend(scan_body(
                "\n".join(sources), asset=asset, url=map_url or url, status="",
                source=f"{source}-sourcemap", min_severity=min_severity,
                next_id=next_id, freshness=freshness, dedup=dedup, vibe=vibe,
            ))
    return findings


def read_bodies(
    http: Http,
    assets: list[dict],
    *,
    min_severity: str = "medium",
    next_id: "Callable[[], str] | None" = None,
    dedup: "dict[tuple[str, str, str], int] | None" = None,
    missed_out: "list[str] | None" = None,
    vibe: bool = False,
    log: Callable[[str], None] | None = None,
    done: "dict[str, list[dict]] | None" = None,
    done_missed: "set[str] | None" = None,
    on_result: "Callable[[str, list[dict], bool], None] | None" = None,
) -> tuple[list[Finding], list[str]]:
    """Read ARCHIVED (Wayback) endpoint bodies and run the content rules.

    Passive: the target is never contacted, so medium-confidence apexes are read
    too (not just high).
    ``missed_out`` collects endpoint URLs the archive had no snapshot for, so the
    probe stage can fetch just those live.

    Resume: ``done`` maps an already-processed archive URL to the finding dicts
    it produced; such URLs are replayed (findings rebuilt with fresh ids, miss
    re-recorded) instead of re-fetched. ``on_result`` is called after each freshly
    fetched URL with ``(url, finding_dicts, missed)`` so the caller can persist it.
    """
    say = log or (lambda _: None)
    next_id = next_id or FindingIds("A")
    done = done or {}
    done_missed = done_missed or set()
    problems: list[str] = []

    # Archived reads never touch the target, so medium confidence is allowed.
    targets = _select_targets(assets, None, confidence_rank("medium"))
    findings: list[Finding] = []
    say(f"reading {len(targets)} archived endpoint bodies...")

    for i, asset in enumerate(targets, 1):
        url = asset["url"]

        # Resume: already processed in an interrupted run. Replay (fresh ids).
        if url in done:
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
            status, text = body_src.wayback_body(http, url)
            url_findings: list[Finding] = []
            missed = not text
            if missed and missed_out is not None:
                missed_out.append(url)
            if text:
                url_findings = scan_served_body(
                    http, asset=asset, url=url, text=text, source="wayback-body",
                    status=str(status) if status else "", freshness="archived",
                    min_severity=min_severity, next_id=next_id, dedup=dedup,
                    vibe=vibe, fetch_fn=body_src.wayback_body, log=log,
                )
        except RequestBudgetExceeded as exc:
            problems.append(f"stopped at request cap: {exc}")
            break
        say(f"  ({i}/{len(targets)}) {status or '-'} {url}")

        findings.extend(url_findings)
        if on_result is not None:
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
    see. Being passive, it reads medium-confidence apexes too (``read_bodies``).

    Returns ``(findings, missed, problems)``: ``missed`` is the endpoint URLs
    the archive had no snapshot for, so the ``probe`` stage can fetch just those.
    ``done``/``on_result`` make the pass resumable (see ``read_bodies``).
    """
    next_id = next_id or FindingIds("A")
    dedup: dict[tuple[str, str, str], int] = {}
    missed: list[str] = []
    findings, problems = read_bodies(
        http, assets, min_severity=min_severity,
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
