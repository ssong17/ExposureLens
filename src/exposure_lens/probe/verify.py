"""Verification pass: scan findings -> live status + confirmed exposures.

`scan` says a host or path *looks* sensitive; `verify` checks whether it is
actually reachable right now and, if so, whether a known-exposure path answers
without authentication. It is the bridge the pipeline was missing: host-level
findings (git/CI/monitoring servers) never reach body inspection, because that
reads endpoint bodies, so their liveness went unchecked.

Boundaries this keeps (matching the tool's passive-first stance):
- One GET per probe, redirects not followed, high-confidence apexes only.
- Only paths the finding already implies (rules.VERIFY_PROBES) — no brute force,
  no wordlist, no payload.
- Authorization gaps are reported as "answered 2xx unauthenticated", nothing more.
- Liveness is always recorded, but as its own category: it is an asset property,
  not an exposure, and reports roll it up instead of listing it.
- Secrets found in a body are masked.
"""
from __future__ import annotations

from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from ..core.models import (
    LIVENESS_CATEGORY,
    SEVERITY_ORDER,
    Finding,
    FindingIds,
    confidence_rank,
    timestamp_now,
)
from ..core.net import Http, RequestBudgetExceeded
from ..scan.rules import VERIFY_DEFAULT_PROBE, VERIFY_PROBES, base_severity
from ..scan.scanner import scan_body


def liveness_label(status: int) -> str:
    """Human-readable liveness for a probe status (0 = no response)."""
    if status == 0:
        return "unreachable"
    if 200 <= status < 300:
        return "live"
    if status in (401, 403):
        return "protected"
    if 300 <= status < 400:
        return "redirect"
    return f"http-{status}"


def make_liveness_finding(
    asset_like: dict, url: str, status: int, next_id, *, source: str
) -> Finding:
    """A row recording reachability, regardless of any exposure."""
    label = liveness_label(status)
    # A live answer proves the asset exists now; anything else leaves the
    # collected freshness as it was.
    freshness = "current" if 200 <= status < 400 else asset_like.get("freshness", "")
    return Finding(
        finding_id=next_id(),
        org_id=asset_like.get("org_id", ""),
        asset_ref=asset_like.get("asset_ref", asset_like.get("record_id", "")),
        org_name=asset_like.get("org_name", ""),
        severity="low",
        category=LIVENESS_CATEGORY,
        rule=f"live-{label}",
        host=asset_like.get("host", urlsplit(url).hostname or ""),
        url=url,
        evidence=f"{status or '-'} {label}",
        discovered_at=timestamp_now(),
        path=urlsplit(url).path or "/",
        status=str(status) if status else "",
        source=source,
        freshness=freshness,
    )


def _root(host: str) -> str:
    return urlunsplit(("https", host, "/", "", ""))


def _probe_targets(finding: dict) -> list[tuple[str, str, str, str]]:
    """(url, severity, category, rule) probes implied by one scan finding."""
    host = finding.get("host", "")
    url = finding.get("url", "")
    if url:  # an endpoint/path finding: confirm the exact URL it flagged
        # Rule level, not the scan level: a Wayback-only path was lowered as
        # a candidate, but a live unauthenticated hit is present-tense.
        return [(url, base_severity(finding),
                 finding.get("category", "exposure"),
                 f"verify-{finding.get('rule', 'path')}")]
    if not host:
        return []
    probes = VERIFY_PROBES.get(finding.get("rule", ""), VERIFY_DEFAULT_PROBE)
    base = _root(host).rstrip("/")
    return [(base + path, sev, cat, rid) for path, sev, cat, rid in probes]


def verify_findings(
    http: Http,
    findings: list[dict],
    assets_by_id: dict[str, dict] | None = None,
    *,
    min_severity: str = "low",
    max_targets: int = 0,  # 0 = unlimited
    confidence: str = "high",
    next_id: "Callable[[], str] | None" = None,
    dedup: "dict[tuple[str, str, str], int] | None" = None,
    vibe: bool = False,
    log: Callable[[str], None] | None = None,
) -> tuple[list[Finding], list[str]]:
    """Return (verify findings incl. liveness rows, problems).

    Only findings whose asset is at or above ``confidence`` are probed (default
    high), because verify touches the target and we never want to hit a host that
    might belong to another organization. ``assets_by_id`` (record_id -> asset)
    supplies that confidence when present.
    """
    say = log or (lambda _: None)
    next_id = next_id or FindingIds("V")
    problems: list[str] = []
    assets_by_id = assets_by_id or {}
    limit = SEVERITY_ORDER[min_severity]
    conf_limit = confidence_rank(confidence)

    # De-duplicate probe URLs across findings; keep the strongest implied weight.
    plan: dict[str, tuple[str, str, str, dict]] = {}  # url -> (sev,cat,rule,finding)
    skipped_conf = 0
    for finding in findings:
        if finding.get("category") == LIVENESS_CATEGORY:
            continue  # don't re-verify our own output
        asset = assets_by_id.get(finding.get("asset_ref", ""), {})
        conf = asset.get("apex_confidence", finding.get("apex_confidence", "high"))
        if confidence_rank(conf) > conf_limit:
            skipped_conf += 1
            continue
        for url, sev, cat, rule in _probe_targets(finding):
            prev = plan.get(url)
            if prev is None or SEVERITY_ORDER[sev] < SEVERITY_ORDER[prev[0]]:
                plan[url] = (sev, cat, rule, finding)
    if skipped_conf:
        problems.append(
            f"skipped {skipped_conf} findings below confidence '{confidence}'"
        )

    targets = list(plan.items())
    if max_targets and len(targets) > max_targets:
        problems.append(f"capped targets {max_targets}/{len(targets)}")
        targets = targets[:max_targets]

    out: list[Finding] = []
    say(f"verifying {len(targets)} probes (confidence>={confidence})...")
    for url, (sev, cat, rule, finding) in targets:
        try:
            status, text, _ct, _loc = http.probe(url)
        except RequestBudgetExceeded as exc:
            problems.append(f"stopped at request cap: {exc}")
            break
        say(f"  {status or '-':<4} {url}")
        host = urlsplit(url).hostname or finding.get("host", "")

        # Liveness is always recorded.
        out.append(make_liveness_finding(
            {**finding, "host": host}, url, status, next_id, source="verify-status",
        ))

        # Confirmed exposure: a known-exposure path answered unauthenticated.
        if 200 <= status < 300 and SEVERITY_ORDER[sev] <= limit:
            out.append(Finding(
                finding_id=next_id(),
                org_id=finding.get("org_id", ""),
                asset_ref=finding.get("asset_ref", ""),
                org_name=finding.get("org_name", ""),
                severity=sev,  # type: ignore[arg-type]
                category=cat,
                rule=rule,
                host=host,
                url=url,
                evidence=f"{status} reachable unauthenticated",
                discovered_at=timestamp_now(),
                path=urlsplit(url).path or "/",
                status=str(status),
                source="verify-confirmed",
                freshness="current",  # just proven live by this very request
            ))
            # Read the served body for leaked secrets/config/DB/PII.
            if text:
                out.extend(scan_body(
                    text,
                    asset={
                        "record_id": finding.get("asset_ref", ""),
                        "org_id": finding.get("org_id", ""),
                        "org_name": finding.get("org_name", ""),
                        "host": host,
                    },
                    url=url,
                    status=str(status),
                    source="verify-body",
                    min_severity=min_severity,
                    next_id=next_id,
                    freshness="current",
                    dedup=dedup,
                    vibe=vibe,
                ))

    out.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    say(f"done: {len(out)} rows from {len(targets)} probes")
    return out, problems
