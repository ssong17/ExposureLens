"""Collector: apex discovery -> subdomain enumeration -> Asset records.

Only high/medium apexes are enumerated, capped per org (``max_apex_per_org``)
so large companies do not explode the crt.sh request count. IP resolution and
ASN mapping are added in a later stage.
"""
from __future__ import annotations

import re

from .apex import discover_apex
from .config import CollectorConfig, OrgConfig
from .models import ApexCandidate, Asset, run_date, timestamp_now
from .net import Http, RequestBudgetExceeded
from .sources import crtsh

_ID_SANITIZE = re.compile(r"[^A-Z0-9]+")
TARGET_CONFIDENCES = ("high", "medium")
_RANK = {"high": 0, "medium": 1}


def _prefix(org_id: str) -> str:
    return _ID_SANITIZE.sub("_", org_id.upper()).strip("_") or "ORG"


def select_target_apexes(
    candidates: list[ApexCandidate], limit: int
) -> list[ApexCandidate]:
    targets = [c for c in candidates if c.confidence in TARGET_CONFIDENCES]
    targets.sort(key=lambda c: (_RANK[c.confidence], -c.cert_count))
    return targets[:limit]


def collect_org(
    http: Http, org: OrgConfig, collector: CollectorConfig
) -> tuple[list[Asset], list[str]]:
    """Return (assets, problems) for one organization."""
    candidates, errors = discover_apex(http, org)
    problems = [f"[{org.org_id}] {e}" for e in errors]
    if not candidates:
        problems.append(f"[{org.org_id}] no apex candidates")
        return [], problems

    targets = select_target_apexes(candidates, collector.max_apex_per_org)
    eligible = sum(1 for c in candidates if c.confidence in TARGET_CONFIDENCES)
    if eligible > len(targets):
        problems.append(
            f"[{org.org_id}] capped apexes {len(targets)}/{eligible} "
            "(max_apex_per_org)"
        )

    prefix = _prefix(org.org_id)
    date = run_date()
    at = timestamp_now()
    seen: set[str] = set()
    assets: list[Asset] = []

    for cand in targets:
        try:
            hosts = crtsh.domain_search(http, cand.apex)
        except RequestBudgetExceeded as exc:
            problems.append(f"[{org.org_id}] stopped at request cap: {exc}")
            break
        except Exception as exc:  # noqa: BLE001 - report source failures in summary
            problems.append(f"[{org.org_id}] crt.sh %.{cand.apex}: {exc}")
            continue
        for host in sorted(hosts):
            if host in seen:
                continue
            seen.add(host)
            assets.append(
                Asset(
                    record_id=f"{prefix}_{date}_{len(assets) + 1:06d}",
                    org_id=org.org_id,
                    apex=cand.apex,
                    apex_confidence=cand.confidence,
                    asset_type="apex" if host == cand.apex else "subdomain",
                    host=host,
                    source="crt.sh",
                    discovered_at=at,
                )
            )

    if not assets:
        problems.append(f"[{org.org_id}] no subdomains collected")
    return assets, problems
