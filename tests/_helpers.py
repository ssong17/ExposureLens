"""Shared test helpers (not fixtures) — imported explicitly by test modules.

``run_scan_body`` removes the scan_body boilerplate that four rule-focused
test files repeated; each keeps its own thin ``_body`` wrapper so its exact
url/source/id choices stay visible and unchanged.
"""
from __future__ import annotations

from exposure_lens.scan.scanner import scan_body

_DEFAULT_ASSET = {"record_id": "R", "org_id": "x", "host": "h"}


def run_scan_body(
    text: str,
    *,
    next_id,
    url: str = "https://h/app.js",
    source: str = "fetch-body",
    min_severity: str = "low",
    freshness: str = "",
    asset: dict | None = None,
):
    """Call scan_body with test defaults; callers override what they care about."""
    return scan_body(
        text,
        asset=asset or _DEFAULT_ASSET,
        url=url,
        status="200",
        source=source,
        min_severity=min_severity,
        next_id=next_id,
        freshness=freshness,
    )
