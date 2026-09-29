"""Content inspection — the tool's single active stage ("probe").

This is the "read what the address serves" pass that the passive `scan` cannot
do on the URL alone. It never guesses new paths and never sends a payload: it
takes assets and findings already collected, retrieves each body (archived
snapshot by default, or one direct GET when explicitly allowed), and runs the
content rules over the result.

``run_inspection`` is the one entry point. It folds both halves of the active
work together:

  1. endpoint bodies -> secrets / config / DB / PII / client-code surface,
     following a source map when one is referenced;
  2. verification of existing scan findings -> reachability and known-exposure
     paths answering unauthenticated.

Both the ``probe`` command and ``run --probe`` call it, so the two can no longer
disagree about what "active" means — previously ``run --probe`` ran only step 2
and silently skipped every body, JS and secret check.

Safety gates, all enforced here rather than at the call sites:
- direct fetches only for high-confidence apexes, so we never touch a host that
  might belong to another organization;
- one GET per URL, redirects not followed, no payloads, no path guessing.
"""
from __future__ import annotations

import base64
import binascii
import json
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
from ..sources import body as body_src
from ..scan.rules import AUTHZ_PATH, base_severity
from ..scan.scanner import scan_body
from .verify import make_liveness_finding, verify_findings

WAYBACK = "wayback"
FETCH = "fetch"

_SOURCEMAP_REF = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

# Client-code endpoints worth reading for the JS/authz/surface rules — the
# script bundles and source maps where routes and auth checks actually live.
_SCRIPT_EXT = {"js", "mjs", "cjs", "ts", "json", "map"}


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


# Keep at most this many query-string variants of one (host, path). The 455
# `?page=1..N` copies of one template all serve the same body, so probing every
# one cost ~4h and (before dedup) reported the same secret hundreds of times. A
# few variants still cover the case where the query genuinely changes the body.
_MAX_VARIANTS_PER_PATH = 3


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


def inspect_assets(
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
    log: Callable[[str], None] | None = None,
) -> tuple[list[Finding], list[str]]:
    """Body-reading half of the active stage. ``source`` is WAYBACK or FETCH.

    ``dedup`` (see ``scan_body``) collapses one templated secret across pages.
    ``missed_out``: on a WAYBACK pass, endpoint URLs the archive had no snapshot
    for are appended here, so the caller's active pass can fetch just those live
    (the "catch what passive missed" half of the flow).
    """
    say = log or (lambda _: None)
    next_id = next_id or FindingIds("I")
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
    say(f"inspecting {len(targets)} endpoints via {source}...")

    for i, asset in enumerate(targets, 1):
        url = asset["url"]
        try:
            if source == FETCH:
                status, text = body_src.fetch_body(http, url)
            else:
                status, text = body_src.wayback_body(http, url)
        except RequestBudgetExceeded as exc:
            problems.append(f"stopped at request cap: {exc}")
            break
        say(f"  ({i}/{len(targets)}) {status or '-'} {url}")

        # Archive had no usable snapshot for this URL: note it so a later active
        # pass can fetch it live (passive could not see it).
        if source == WAYBACK and not text and missed_out is not None:
            missed_out.append(url)

        # A direct fetch always yields a liveness signal; record it even when the
        # body is clean so the report can rank live exposures above stale ones.
        if source == FETCH:
            findings.append(
                make_liveness_finding(asset, url, status, next_id,
                                      source="fetch-status")
            )

        # Authorization gap: a should-be-protected path that answers 2xx.
        if source == FETCH and 200 <= status < 300 and AUTHZ_PATH.search(url):
            findings.append(_authz_finding(asset, url, status, next_id))

        if not text:
            continue
        # A body we just fetched is being served now; an archived snapshot is not.
        body_freshness = "current" if source == FETCH else "archived"
        findings.extend(
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
            )
        )

        # Follow a source map: minified bundles hide routes/authz from the rules,
        # but the map's original sources restore them. This is the recall move.
        if "sourceMappingURL" in text:
            fetch_fn = body_src.fetch_body if source == FETCH else body_src.wayback_body
            try:
                map_url, sources = _read_sourcemap(fetch_fn, http, url, text)
            except RequestBudgetExceeded as exc:
                problems.append(f"stopped at request cap: {exc}")
                break
            if sources:
                say(f"      sourcemap: {len(sources)} sources <- {map_url}")
                findings.extend(
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
                    )
                )

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    say(f"done: {len(findings)} findings from {len(targets)} endpoints")
    return findings, problems


@dataclass
class InspectionResult:
    """What one active pass produced, with reachability kept separate."""

    findings: list[Finding] = field(default_factory=list)
    liveness: list[Finding] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    # Endpoint URLs the archive had no snapshot for (WAYBACK pass only). The
    # active pass fetches these live to cover what passive could not see.
    missed: list[str] = field(default_factory=list)

    @property
    def rows(self) -> list[Finding]:
        return [*self.findings, *self.liveness]

    @property
    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.source == "verify-confirmed"]


def run_inspection(
    http: Http,
    assets: list[dict],
    prior_findings: list[dict] | None = None,
    *,
    source: str = FETCH,
    min_severity: str = "low",
    confidence: str = "high",
    max_targets: int = 0,  # 0 = unlimited
    scripts_only: bool = False,
    only_findings: bool = False,
    restrict_body_urls: set[str] | None = None,
    log: Callable[[str], None] | None = None,
) -> InspectionResult:
    """The whole active stage: body inspection + finding verification.

    One ``FindingIds`` allocator is shared by both halves, so ids are unique
    across the run.

    ``restrict_body_urls`` (when not None) limits body reads to exactly those
    URLs — the pipeline passes the archive's misses here so a FETCH pass reads
    only what passive could not. On a WAYBACK pass the archive's misses are
    recorded in ``result.missed`` for that later FETCH pass.
    """
    prior_findings = prior_findings or []
    next_id = FindingIds("P")
    result = InspectionResult()
    # One dedup map for the whole pass: a secret in a shared template is counted
    # per org, reported once (see scan_body). Shared by body inspection and
    # verification so a value seen by both is not emitted twice.
    dedup: dict[tuple[str, str, str], int] = {}

    if restrict_body_urls is not None:
        finding_urls: set[str] | None = restrict_body_urls
    elif only_findings:
        finding_urls = {
            f.get("url", "") for f in prior_findings
            # base_severity: an archived .git path scanned as a medium
            # candidate is exactly what this pass exists to check.
            if f.get("url") and base_severity(f) in ("critical", "high")
        }
    else:
        finding_urls = None

    # 1) endpoint bodies -> secrets/config/DB/PII/JS/authz (+ liveness in fetch)
    rows, problems = inspect_assets(
        http, assets, source=source, min_severity=min_severity,
        finding_urls=finding_urls, max_targets=max_targets,
        scripts_only=scripts_only, next_id=next_id, dedup=dedup,
        missed_out=result.missed if source == WAYBACK else None, log=log,
    )
    result.problems.extend(problems)

    # 2) scan findings -> reachability + known-exposure paths + unauth access.
    # Verification always sends live requests, so it only runs on a FETCH pass.
    if prior_findings and source == FETCH:
        assets_by_id = {a.get("record_id", ""): a for a in assets}
        ver, vproblems = verify_findings(
            http, prior_findings, assets_by_id, min_severity=min_severity,
            confidence=confidence, max_targets=max_targets,
            next_id=next_id, dedup=dedup, log=log,
        )
        rows.extend(ver)
        result.problems.extend(vproblems)

    rows = _annotate_duplicates(rows, dedup)
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


def _annotate_duplicates(
    rows: list[Finding], dedup: dict[tuple[str, str, str], int]
) -> list[Finding]:
    """Append '(+N pages)' to a finding whose secret recurred on other pages."""
    from dataclasses import replace
    out: list[Finding] = []
    for f in rows:
        extra = dedup.get((f.org_id, f.rule, f.evidence), 1) - 1
        if extra > 0:
            f = replace(f, evidence=f"{f.evidence} (+{extra} pages)")
        out.append(f)
    return out
