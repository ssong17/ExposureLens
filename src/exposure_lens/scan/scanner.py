"""Passive exposure scanner: collected assets -> findings.

Applies the rule sets to hostnames and endpoint URLs already gathered by the
collector. It never requests the target, never verifies a secret, and masks any
matched secret value. Findings are ranked by severity.
"""
from __future__ import annotations

from typing import Iterable
from urllib.parse import urlsplit

from ..core.models import Finding, run_date, timestamp_now
from .rules import HOST_RULES, PATH_RULES, SECRET_RULES

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _mask(value: str) -> str:
    value = value.strip()
    if "=" in value:  # keep the key, hide the value
        key, _, secret = value.partition("=")
        return f"{key}={_mask(secret)}"
    if len(value) <= 8:
        return value[:2] + "****"
    return value[:4] + "****" + value[-2:]


def scan_assets(
    assets: Iterable[dict], *, min_severity: str = "medium"
) -> list[Finding]:
    limit = SEVERITY_ORDER[min_severity]
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for asset in assets:
        asset_type = asset.get("asset_type", "")
        host = asset.get("host", "")
        url = asset.get("url", "")
        matches: list[tuple[str, str, str, str, str]] = []  # id,cat,sev,evidence,url

        if asset_type in ("subdomain", "apex"):
            for rule in HOST_RULES:
                if rule.pattern.search(host):
                    matches.append((rule.id, rule.category, rule.severity, host, ""))
        elif asset_type == "endpoint" and url:
            path = urlsplit(url).path
            for rule in PATH_RULES:
                if rule.pattern.search(path):
                    matches.append((rule.id, rule.category, rule.severity, path, url))
            for rule in SECRET_RULES:
                found = rule.pattern.search(url)
                if found:
                    ev = _mask(found.group(0))
                    matches.append((rule.id, rule.category, rule.severity, ev, url))

        for rule_id, category, severity, evidence, hit_url in matches:
            if SEVERITY_ORDER[severity] > limit:
                continue
            key = (asset.get("record_id", ""), rule_id, evidence)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    finding_id=f"F_{run_date()}_{len(findings) + 1:06d}",
                    org_id=asset.get("org_id", ""),
                    asset_ref=asset.get("record_id", ""),
                    severity=severity,  # type: ignore[arg-type]
                    category=category,
                    rule=rule_id,
                    host=host,
                    url=hit_url,
                    evidence=evidence,
                    discovered_at=timestamp_now(),
                )
            )

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings
