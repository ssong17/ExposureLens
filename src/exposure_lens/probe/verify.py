"""Probe helpers: reachability rows and the known-exposure paths a scan finding
implies.

`scan` says a host or path *looks* sensitive; the probe loop (``probe.prober``)
checks whether it is actually reachable right now and, if so, whether a
known-exposure path answers without authentication. This module supplies the two
pieces that loop needs:

- ``make_liveness_finding`` / ``liveness_label`` — the reachability row, recorded
  for every probe regardless of any exposure (it is an asset property, not an
  exposure, so reports roll it up instead of listing it).
- ``implied_probes`` — the EXACT paths one finding implies (rules.VERIFY_PROBES),
  never a guessed word or wordlist: a git host → /.git/config, an endpoint
  finding → its own URL. The probe loop GETs these and, on a 2xx with real
  content, promotes the candidate to a confirmed exposure.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from ..core.models import LIVENESS_CATEGORY, Finding, timestamp_now
from ..scan.rules import VERIFY_DEFAULT_PROBE, VERIFY_PROBES, base_severity


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


def implied_probes(finding: dict) -> list[tuple[str, str, str, str]]:
    """(url, severity, category, rule) probes a scan finding implies.

    An endpoint/path finding confirms its own URL (at rule severity — a
    Wayback-only path was a candidate, but a live unauthenticated hit is
    present-tense). A host-level finding expands to the EXACT paths its rule
    implies (VERIFY_PROBES), never a guess.
    """
    host = finding.get("host", "")
    url = finding.get("url", "")
    if url:
        return [(url, base_severity(finding),
                 finding.get("category", "exposure"),
                 f"verify-{finding.get('rule', 'path')}")]
    if not host:
        return []
    probes = VERIFY_PROBES.get(finding.get("rule", ""), VERIFY_DEFAULT_PROBE)
    base = _root(host).rstrip("/")
    return [(base + path, sev, cat, rid) for path, sev, cat, rid in probes]
