"""Scan-stage exposure rules: collected assets -> findings (never touches the target).

Applies the rule sets to hostnames and endpoint URLs already gathered by the
collector, and (via ``scan_body``) to response bodies another stage retrieved.
It never requests the target itself, never verifies a secret, and masks any
matched secret value. Findings are ranked by severity.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import replace
from typing import Iterable
from urllib.parse import urlsplit

from ..core.models import (
    SEVERITY_ORDER,
    Finding,
    downgrade,
    run_date,
    timestamp_now,
)
from .rules import (
    CLIENT_RULES,
    CONTENT_RULES,
    ENTROPY_CHECKED_RULES,
    HOST_RULES,
    MAX_MATCHES_PER_RULE,
    MIN_SECRET_ENTROPY,
    PATH_RULES,
    PLACEHOLDER_MARKERS,
    PLACEHOLDER_TOKENS,
    PUBLIC_BROWSER_KEY,
    SECRET_RULES,
)
from .vibe_rules import detect_body as vibe_detect_body
from .vibe_rules import detect_host as vibe_detect_host

# Only credential-bearing categories are masked; a route/URL/authz-check IS the
# finding, so it is kept verbatim (just length-capped).
_MASK_CATEGORIES = {"leaked-secret", "hardcoded-secret", "db-exposure", "pii-exposure"}
# Host findings come from the NAME alone, which cannot tell git-the-tool from
# "GIT" the acronym, or an open service from a login-gated VPN portal. So a name
# match is a CANDIDATE, capped here; only `probe` (an actual unauthenticated
# 2xx) promotes it back to high/critical. Keeps ranking honest.
_CANDIDATE_CAP = "medium"

_ASSIGN = re.compile(r"^(.*?[:=]\s*[\"']?)(.+?)([\"']?)$", re.DOTALL)
# The value side of an assignment/header match, for the placeholder/entropy test.
_VALUE = re.compile(
    r"(?:[:=]\s*|\bbearer\s+|\bbasic\s+)[\"']?([^\"'\s]+)[\"']?\s*$",
    re.IGNORECASE | re.DOTALL,
)
# Value segments, split on the separators people actually use in config keys.
_SEGMENT = re.compile(r"[^a-z0-9]+")
_TRAILING_DIGITS = re.compile(r"\d+$")


def _shannon_entropy(value: str) -> float:
    """Bits of entropy per character. ~0 for 'aaaa', ~4+ for a real key."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (n / length) * math.log2(n / length) for n in counts.values()
    )


def _secret_value(raw: str) -> str:
    """The candidate secret inside a matched assignment/header, else the match."""
    found = _VALUE.search(raw.strip())
    return found.group(1) if found else raw.strip()


def is_placeholder(value: str) -> bool:
    """True when a secret-shaped value is obviously not a secret.

    Matching is on whole separator-delimited segments, never on substrings:
    "YOUR_API_KEY" and "test-token-value" are placeholders, but a real random
    key that happens to contain the letters "foo" or "abc" is not. Erring the
    other way would silently discard real secrets, which is the expensive miss.
    """
    value = value.strip().strip("\"'")
    if not value:
        return True
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    if len(set(value)) <= 2:  # 'xxxxxxxx', '00000000'
        return True
    segments = [seg for seg in _SEGMENT.split(lowered) if seg]
    if not segments:
        return True
    # "changeme123" / "secret1": a trailing counter does not make it real.
    variants = {lowered, *segments}
    variants |= {_TRAILING_DIGITS.sub("", seg) for seg in segments}
    return bool(variants & PLACEHOLDER_TOKENS)


def is_credible_secret(rule_id: str, raw: str) -> bool:
    """Precision gate for generic secret shapes; structural rules pass through."""
    if rule_id not in ENTROPY_CHECKED_RULES:
        return True
    value = _secret_value(raw)
    # A public-by-design browser key (AIza…/reCAPTCHA 6L…) is not a credential,
    # even when wrapped in an apiKey/secret assignment. It is surfaced low by a
    # dedicated rule instead of topping the report as a "leaked secret".
    if PUBLIC_BROWSER_KEY.match(value):
        return False
    if len(value) < 8 or is_placeholder(value):
        return False
    return _shannon_entropy(value) >= MIN_SECRET_ENTROPY


def _mask(value: str) -> str:
    value = value.strip()
    if "=" in value:  # keep the key, hide the value
        key, _, secret = value.partition("=")
        return f"{key}={_mask(secret)}"
    if len(value) <= 8:
        return value[:2] + "****"
    return value[:4] + "****" + value[-2:]


def _mask_match(value: str) -> str:
    """Mask a body match, keeping any leading key/delimiter for triage."""
    value = value.strip()
    assign = _ASSIGN.match(value)
    if assign:  # e.g.  password: "hunter2"  ->  password: "hu****"
        prefix, secret, suffix = assign.groups()
        return f"{prefix}{_mask(secret)}{suffix}"
    if len(value) <= 8:
        return value[:2] + "****"
    return value[:4] + "****" + value[-2:]


def scan_assets(
    assets: Iterable[dict], *, min_severity: str = "medium", vibe: bool = False
) -> list[Finding]:
    limit = SEVERITY_ORDER[min_severity]
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    # (org, host, rule, path) -> index into findings. One archived page crawled
    # with 40 query strings is one path, not 40 findings.
    path_rows: dict[tuple[str, str, str, str], int] = {}
    variants: Counter[int] = Counter()

    for asset in assets:
        asset_type = asset.get("asset_type", "")
        host = asset.get("host", "")
        url = asset.get("url", "")
        # A host asset with no resolved IP did not resolve at collection time.
        dead_host = asset_type in ("subdomain", "apex") and not asset.get("resolved_ip")
        # id, cat, sev, evidence, url, path  (url is always a full openable URL)
        matches: list[tuple[str, str, str, str, str, str]] = []

        if asset_type in ("subdomain", "apex"):
            host_url = f"https://{host}/"  # openable even for a host-only finding
            for rule in HOST_RULES:
                if rule.pattern.search(host):
                    sev = rule.severity
                    if SEVERITY_ORDER[sev] < SEVERITY_ORDER[_CANDIDATE_CAP]:
                        sev = _CANDIDATE_CAP  # name match is a candidate, not proof
                    if dead_host:
                        sev = downgrade(sev)
                    ev = f"{host} (dns-unresolved)" if dead_host else host
                    matches.append((rule.id, rule.category, sev, ev, host_url, "/"))
            if vibe:
                # Vibe-coding platform fingerprints by hostname (free; domain
                # signatures). Attribution, so low severity.
                for sig in vibe_detect_host(host):
                    matches.append((
                        f"vibe-{sig.name}", "vibe-platform", "low",
                        f"{sig.platform}: {sig.description} ({sig.confidence})",
                        host_url, "/",
                    ))
        elif asset_type == "endpoint" and url:
            path = urlsplit(url).path
            # Only Wayback knows this URL: it existed once, which is a lead for
            # `probe`, not a file seen today. One notch down, like a dead host.
            archived = asset.get("freshness") == "archived"
            best: dict[str, tuple[str, str, str, str, str, str]] = {}
            for rule in PATH_RULES:
                if not rule.pattern.search(path):
                    continue
                sev = downgrade(rule.severity) if archived else rule.severity
                prev = best.get(rule.category)
                # One row per kind per URL: /backups/x.tgz is a backup archive,
                # not also a separate "backup directory" finding.
                if prev is None or SEVERITY_ORDER[sev] < SEVERITY_ORDER[prev[2]]:
                    ev = f"{path} (archived)" if archived else path
                    best[rule.category] = (rule.id, rule.category, sev, ev, url, path)
            matches.extend(best.values())
            for rule in SECRET_RULES:
                found = rule.pattern.search(url)
                if found and is_credible_secret(rule.id, found.group(0)):
                    ev = _mask(found.group(0))
                    matches.append(
                        (rule.id, rule.category, rule.severity, ev, url, path)
                    )

        for rule_id, category, severity, evidence, hit_url, hit_path in matches:
            if SEVERITY_ORDER[severity] > limit:
                continue
            key = (asset.get("record_id", ""), rule_id, evidence)
            if key in seen:
                continue
            seen.add(key)
            if rule_id.startswith("path-"):
                pkey = (asset.get("org_id", ""), host, rule_id, hit_path)
                if pkey in path_rows:
                    variants[path_rows[pkey]] += 1
                    continue
                path_rows[pkey] = len(findings)
            findings.append(
                Finding(
                    finding_id=f"F_{run_date()}_{len(findings) + 1:06d}",
                    org_id=asset.get("org_id", ""),
                    asset_ref=asset.get("record_id", ""),
                    org_name=asset.get("org_name", ""),
                    severity=severity,  # type: ignore[arg-type]
                    category=category,
                    rule=rule_id,
                    host=host,
                    url=hit_url,
                    evidence=evidence,
                    discovered_at=timestamp_now(),
                    path=hit_path,
                    freshness=asset.get("freshness", ""),
                )
            )

    for i, extra in variants.items():
        findings[i] = replace(
            findings[i], evidence=f"{findings[i].evidence} (+{extra} query variants)"
        )
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings


def scan_body(
    text: str,
    *,
    asset: dict,
    url: str,
    status: str,
    source: str,
    min_severity: str = "medium",
    next_id,
    freshness: str = "",
    dedup: "dict[tuple[str, str, str], int] | None" = None,
    vibe: bool = False,
) -> list[Finding]:
    """Apply CONTENT_RULES/CLIENT_RULES to one response body already fetched.

    ``text`` is the served content (a JS bundle, config file, JSON response, or
    archived page). Every credential match is masked before it is stored, and
    nothing here contacts the target — the caller supplies the body.
    ``next_id`` is the run-wide id allocator (see ``FindingIds``) so ids stay
    unique no matter how many stages emit findings into one run.

    ``dedup`` collapses the SAME secret across bodies. One token embedded in a
    shared header/footer template appears on every page; without this a run over
    455 pages reported one JWT 455 times and buried the real findings. When
    passed (a run-wide dict keyed ``(org_id, rule_id, evidence)``), the first
    body to hit a value emits the finding and later bodies only bump its count.
    """
    limit = SEVERITY_ORDER[min_severity]
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    org_id = asset.get("org_id", "")
    host = asset.get("host", "")
    record_id = asset.get("record_id", "")
    path = urlsplit(url).path
    # The body was served by this URL right now (fetch) or in an archive; the
    # caller knows which, and a finding without that context cannot be ranked.
    freshness = freshness or asset.get("freshness", "")

    for rule in (*CONTENT_RULES, *CLIENT_RULES):
        if SEVERITY_ORDER[rule.severity] > limit:
            continue
        hits = 0
        for found in rule.pattern.finditer(text):
            raw = found.group(0)
            if not is_credible_secret(rule.id, raw):
                continue
            if rule.category in _MASK_CATEGORIES:
                evidence = _mask_match(raw)
            else:
                evidence = " ".join(raw.split())[:160]  # verbatim, length-capped
            key = (rule.id, evidence)
            if key in seen:
                continue
            seen.add(key)
            # Same value already reported for this org (another page's copy of a
            # templated token): count it, do not emit a second finding.
            if dedup is not None:
                gkey = (org_id, rule.id, evidence)
                if gkey in dedup:
                    dedup[gkey] += 1
                    continue
                dedup[gkey] = 1
            hits += 1
            if hits > MAX_MATCHES_PER_RULE:
                break
            findings.append(
                Finding(
                    finding_id=next_id(),
                    org_id=asset.get("org_id", ""),
                    asset_ref=record_id,
                    org_name=asset.get("org_name", ""),
                    severity=rule.severity,  # type: ignore[arg-type]
                    category=rule.category,
                    rule=rule.id,
                    host=host,
                    url=url,
                    evidence=evidence,
                    discovered_at=timestamp_now(),
                    path=path,
                    status=status,
                    source=source,
                    freshness=freshness,
                )
            )

    if vibe:
        # Vibe-coding platform fingerprints in the served body (html/js
        # signatures). Attribution → low severity, not masked.
        for sig in vibe_detect_body(text):
            key = (f"vibe-{sig.name}", sig.platform)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    finding_id=next_id(),
                    org_id=org_id,
                    asset_ref=record_id,
                    org_name=asset.get("org_name", ""),
                    severity="low",
                    category="vibe-platform",
                    rule=f"vibe-{sig.name}",
                    host=host,
                    url=url,
                    evidence=f"{sig.platform}: {sig.description} ({sig.confidence})",
                    discovered_at=timestamp_now(),
                    path=path,
                    status=status,
                    source=source,
                    freshness=freshness,
                )
            )
    return findings
