"""The ``probe`` stage: one live pass over everything worth touching.

``probe`` is the tool's one target-touching stage: it sends live GETs to check
CURRENT exposure, where ``scan`` only has the URL/host name and archived
snapshots. ``run_probe`` is a SINGLE pass — there is no separate "read bodies"
and "verify findings" step any more. It builds one target set and GETs each URL
exactly once:

  1. every collected endpoint (both current and archived freshness — the live
     response is what establishes present truth);
  2. plus, for a scan finding that has no endpoint URL (a host/port candidate
     like ``git.x.com`` or an open port), the EXACT paths that finding implies
     (``verify.implied_probes`` → /.git/config, …) — never a guessed path.

For each target it records reachability, then on a 2xx that serves this path's
REAL content (not an SPA/soft-404 fallback) it: confirms a known-exposure path
(or flags a reachable login panel as a credential-stuffing surface), checks for
broken access control, and runs the content rules over the body (following a
source map). It also reads the host homepage once — reused as the SPA baseline
AND to pull the same-origin ``<script src>`` the archive never indexed (all of
them by default; each is its own GET, spaced by the per-host throttle).

Safety gates:
- live fetches only for high-confidence apexes, so we never touch a host that
  might belong to another organization;
- one GET per URL, redirects not followed, no payloads, no path guessing beyond
  the exact paths a finding already implies and same-origin scripts a page links;
- cross-origin (CDN) scripts are never fetched — only the target's own origin.
Per-host request spacing (core.net throttle) keeps the pass polite even when a
page links many scripts — volume becomes elapsed time, not a burst.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlsplit

from ..core.models import (
    SEVERITY_ORDER,
    Finding,
    FindingIds,
    confidence_rank,
    is_liveness,
    timestamp_now,
)
from ..core.net import Http, RequestBudgetExceeded
from ..scan.bodyscan import (
    _is_static_asset,
    _looks_like,
    _looks_like_login,
    _select_targets,
    annotate_duplicates,
    scan_served_body,
)
from ..scan.rules import AUTHZ_PATH, base_severity
from ..sources import body as body_src
from .verify import implied_probes, make_liveness_finding

# Confidence floor for the probe stage: live fetches touch the target, so only
# high-confidence apexes are ever probed. Fixed, no longer operator-tunable.
PROBE_CONFIDENCE = "high"

# Same-origin scripts a homepage links but the archive never indexed. Each one
# is its own GET (the homepage only lists their URLs), so coverage of "public
# scripts" means one request per script — but core.net already spaces requests
# per host (request_interval_seconds), so reading them ALL is polite, not a
# flood. Default reads every same-origin script; a positive cap bounds a
# pathological page that links hundreds. Cross-origin (CDN) scripts are never
# fetched — we read the target's own origin only.
_SCRIPT_SRC = re.compile(r"<script[^>]+\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
SCRIPT_HOP_ALL = 0  # 0 = read every same-origin script the homepage links


@dataclass
class ProbeResult:
    """What one probe pass produced, with reachability kept separate."""

    findings: list[Finding] = field(default_factory=list)
    liveness: list[Finding] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def rows(self) -> list[Finding]:
        return [*self.findings, *self.liveness]

    @property
    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.source == "verify-confirmed"]


@dataclass
class _Target:
    url: str
    ctx: dict            # org/host identity for findings (asset or finding)
    implied: tuple | None = None   # (severity, category, rule) a finding implies
    kind: str = "endpoint"         # endpoint | implied | script


def _authz_finding(ctx: dict, url: str, status: int, next_id) -> Finding:
    return Finding(
        finding_id=next_id(),
        org_id=ctx.get("org_id", ""),
        asset_ref=ctx.get("asset_ref", ctx.get("record_id", "")),
        org_name=ctx.get("org_name", ""),
        severity="high",
        category="access-control",
        rule="authz-open",
        host=ctx.get("host", urlsplit(url).hostname or ""),
        url=url,
        evidence=f"{status} unauthenticated on protected path",
        discovered_at=timestamp_now(),
        path=urlsplit(url).path or "/",
        status=str(status),
        source="fetch-status",
        freshness="current",
    )


def _auth_panel_finding(ctx: dict, url: str, status: int, next_id) -> Finding:
    """A reachable login/auth page — not "open", but a credential-stuffing /
    brute-force surface worth recording (medium candidate)."""
    return Finding(
        finding_id=next_id(),
        org_id=ctx.get("org_id", ""),
        asset_ref=ctx.get("asset_ref", ctx.get("record_id", "")),
        org_name=ctx.get("org_name", ""),
        severity="medium",
        category="auth-panel",
        rule="auth-panel",
        host=ctx.get("host", urlsplit(url).hostname or ""),
        url=url,
        evidence=f"{status} reachable login/auth page",
        discovered_at=timestamp_now(),
        path=urlsplit(url).path or "/",
        status=str(status),
        source="fetch-status",
        freshness="current",
    )


def _confirmed_finding(ctx: dict, url: str, status: int, spec: tuple, next_id) -> Finding:
    sev, cat, rule = spec
    return Finding(
        finding_id=next_id(),
        org_id=ctx.get("org_id", ""),
        asset_ref=ctx.get("asset_ref", ctx.get("record_id", "")),
        org_name=ctx.get("org_name", ""),
        severity=sev,  # type: ignore[arg-type]
        category=cat,
        rule=rule,
        host=ctx.get("host", urlsplit(url).hostname or ""),
        url=url,
        evidence=f"{status} reachable unauthenticated",
        discovered_at=timestamp_now(),
        path=urlsplit(url).path or "/",
        status=str(status),
        source="verify-confirmed",
        freshness="current",
    )


def _finding_ctx(finding: dict) -> dict:
    """Identity fields carried onto probes derived from a scan finding."""
    return {
        "org_id": finding.get("org_id", ""),
        "org_name": finding.get("org_name", ""),
        "asset_ref": finding.get("asset_ref", ""),
        "host": finding.get("host", ""),
        "freshness": finding.get("freshness", ""),
    }


def _build_targets(
    assets: list[dict],
    prior_findings: list[dict],
    *,
    scripts_only: bool,
    only_findings: bool,
) -> list[_Target]:
    """One URL set to GET: collected endpoints + the exact paths host/port
    findings imply. A path/host finding whose URL is already a collected endpoint
    just attaches its implied-exposure spec to that one target (one GET serves
    both body-reading and confirmation)."""
    finding_urls: set[str] | None = None
    if only_findings:
        finding_urls = {
            f.get("url", "") for f in prior_findings
            if f.get("url") and base_severity(f) in ("critical", "high")
        }

    by_url: dict[str, _Target] = {}
    rank = confidence_rank(PROBE_CONFIDENCE)
    for asset in _select_targets(assets, finding_urls, rank, scripts_only):
        by_url[asset["url"]] = _Target(url=asset["url"], ctx=asset)

    assets_by_id = {a.get("record_id", ""): a for a in assets}
    for finding in prior_findings:
        if is_liveness(finding):
            continue
        asset = assets_by_id.get(finding.get("asset_ref", ""), {})
        conf = asset.get("apex_confidence", finding.get("apex_confidence", "high"))
        if confidence_rank(conf) > rank:
            continue  # never probe a host that might not be this org's
        for url, sev, cat, rule in implied_probes(finding):
            spec = (sev, cat, rule)
            existing = by_url.get(url)
            if existing is None:
                by_url[url] = _Target(url, _finding_ctx(finding), spec, "implied")
            elif existing.implied is None or (
                SEVERITY_ORDER[sev] < SEVERITY_ORDER[existing.implied[0]]
            ):
                existing.implied = spec  # confirm this known-exposure on its GET
    return list(by_url.values())


def run_probe(
    http: Http,
    assets: list[dict],
    prior_findings: list[dict] | None = None,
    *,
    min_severity: str = "low",
    max_targets: int = 0,  # 0 = unlimited
    scripts_only: bool = False,
    only_findings: bool = False,
    script_hop: int = SCRIPT_HOP_ALL,
    vibe: bool = False,
    log: Callable[[str], None] | None = None,
) -> ProbeResult:
    """The whole probe stage in one pass. See the module docstring.

    ``script_hop`` bounds how many same-origin ``<script src>`` per host are
    pulled live beyond what collect found: 0 (default) reads them ALL, a positive
    N caps a pathological page. Requests are spaced by the core.net per-host
    throttle, so reading all is polite. One ``FindingIds`` + one dedup map span
    the pass so ids are unique and a templated secret is reported once.
    """
    say = log or (lambda _: None)
    prior_findings = prior_findings or []
    next_id = FindingIds("P")
    dedup: dict[tuple[str, str, str], int] = {}
    result = ProbeResult()
    limit = SEVERITY_ORDER[min_severity]

    worklist = _build_targets(
        assets, prior_findings, scripts_only=scripts_only, only_findings=only_findings,
    )
    if max_targets and len(worklist) > max_targets:
        result.problems.append(f"capped targets {max_targets}/{len(worklist)}")
        worklist = worklist[:max_targets]
    seen_urls = {t.url for t in worklist}
    rows: list[Finding] = []
    # host -> (homepage length or -1, identity ctx) so the SPA baseline and the
    # <script src> harvest both reuse the one homepage GET per host.
    home: dict[str, int] = {}
    say(f"probing {len(worklist)} targets (live GET, high-confidence apexes)...")

    i = 0
    while i < len(worklist):
        target = worklist[i]
        i += 1
        url, ctx = target.url, target.ctx
        host = urlsplit(url).hostname or ""
        try:
            status, text = body_src.fetch_body(http, url)
        except RequestBudgetExceeded as exc:
            result.problems.append(f"stopped at request cap: {exc}")
            break
        say(f"  ({i}/{len(worklist)}) {status or '-'} {url}")
        rows.append(make_liveness_finding(ctx, url, status, next_id, source="fetch-status"))

        # Homepage once per host: SPA/soft-404 baseline + same-origin script hop.
        if host and host not in home:
            try:
                home[host] = _probe_homepage(
                    http, url, host, ctx, worklist, seen_urls, script_hop, say,
                )
            except RequestBudgetExceeded as exc:
                result.problems.append(f"stopped at request cap: {exc}")
                break

        if not (200 <= status < 300) or not text:
            continue
        # Is this 2xx this path's REAL content, or the host's catch-all index?
        path = urlsplit(url).path or "/"
        if (target.kind != "script" and path != "/" and home.get(host, -1) >= 0
                and _looks_like(len(text), home[host])):
            continue  # index fallback, not this path's content

        is_login = _looks_like_login(text)
        if target.implied is not None:
            # a known-exposure path the finding implied answered live
            if is_login:
                rows.append(_auth_panel_finding(ctx, url, status, next_id))
            elif SEVERITY_ORDER[target.implied[0]] <= limit:
                rows.append(_confirmed_finding(ctx, url, status, target.implied, next_id))
        elif not _is_static_asset(url) and AUTHZ_PATH.search(url):
            if is_login:
                rows.append(_auth_panel_finding(ctx, url, status, next_id))
            else:
                rows.append(_authz_finding(ctx, url, status, next_id))

        # Content rules over the served body (+ its source map), always.
        try:
            rows.extend(scan_served_body(
                http, asset=ctx, url=url, text=text, source="fetch-body",
                status=str(status), freshness="current", min_severity=min_severity,
                next_id=next_id, dedup=dedup, vibe=vibe,
                fetch_fn=body_src.fetch_body, log=log,
            ))
        except RequestBudgetExceeded as exc:
            result.problems.append(f"stopped at request cap: {exc}")
            break

    rows = annotate_duplicates(rows, dedup)
    suppressed = sum(n - 1 for n in dedup.values() if n > 1)
    if suppressed:
        result.problems.append(
            f"같은 시크릿이 여러 페이지에 반복돼 {suppressed}건을 합쳤습니다 "
            f"(finding당 '(+N pages)'로 표시)"
        )
    for row in rows:
        (result.liveness if is_liveness(row) else result.findings).append(row)
    result.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return result


def _probe_homepage(
    http: Http, url: str, host: str, ctx: dict, worklist: list[_Target],
    seen_urls: set[str], script_hop: int, say: Callable[[str], None],
) -> int:
    """GET the host root once; return its body length (-1 if not 2xx) for the SPA
    baseline, and queue up to ``script_hop`` same-origin <script src> it links
    that are not already targets. Reuses this one GET for both jobs."""
    parts = urlsplit(url)
    root = f"{parts.scheme}://{parts.netloc}/"
    status, text = body_src.fetch_body(http, root)
    if not (200 <= status < 300):
        return -1
    added = 0
    for m in _SCRIPT_SRC.finditer(text):
        if script_hop and added >= script_hop:  # 0 = unlimited
            break
        src = urljoin(root, m.group(1))
        if urlsplit(src).hostname != host or src in seen_urls:
            continue
        seen_urls.add(src)
        worklist.append(_Target(src, ctx, kind="script"))
        added += 1
    if added:
        say(f"      +{added} same-origin script(s) from {host} homepage")
    return len(text)
