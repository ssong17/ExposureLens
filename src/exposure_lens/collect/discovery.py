"""Apex discovery: organization name -> owned apex candidates with confidence.

crt.sh organization search yields certificates; apexes are ranked by certificate
count and scored:

    high    seed match, or top-ranked apex with a meaningful share
    medium  TLD class matches org_type and count >= MIN_CERTS
    low     everything else (likely sibling orgs or long tail)

Collection keeps medium and above; active scanning should gate on high.
Scoring rationale is recorded in each candidate's ``evidence``.
"""
from __future__ import annotations

from collections import Counter

from ..core.config import OrgConfig
from ..core.models import CONFIDENCE_ORDER, ApexCandidate, timestamp_now
from ..core.net import Http
from ..sources import crtsh
from .tldclass import (
    expected_classes,
    is_infra_apex,
    main_label,
    registrable_apex,
    tld_class,
)

MIN_CERTS = 2
DOMINANT_SHARE = 0.15


def _confidence(
    apex: str, count: int, total: int, is_top: bool, org: OrgConfig,
    seed_labels: frozenset[str],
) -> tuple[str, list[str]]:
    evidence = [f"certs:{count}"]
    tld_match = tld_class(apex) in expected_classes(org.org_type)
    if tld_match:
        evidence.append(f"tld_{tld_class(apex)}")

    if apex in org.seed_domains:
        evidence.append("seed_match")
        return "high", evidence

    share = count / total if total else 0.0
    dominant = is_top and count >= MIN_CERTS and (tld_match or share >= DOMINANT_SHARE)

    # Seed anchoring: when the org's real domains are known, a matching TLD class
    # only says "some school/company", not "this one". An apex from a different
    # registrable family (no shared main label) must earn trust through
    # certificate dominance, not the TLD class alone — this keeps sibling
    # institutions (seoultech.ac.kr vs snu.ac.kr) out of the medium tier.
    anchored = bool(seed_labels)
    related = (not anchored) or (main_label(apex) in seed_labels)
    if anchored and related:
        evidence.append("seed_family")

    # Cert dominance grants high ONLY when unanchored or in the seed family.
    # Otherwise a same-named foreign org that dominates crt.sh (e.g. SOCAR the
    # oil company vs 쏘카 socarcorp.kr) would hijack the collection.
    if dominant and related:
        evidence.append("cert_rank_1")
        return "high", evidence
    if tld_match and count >= MIN_CERTS and related:
        return "medium", evidence
    if tld_match and count >= MIN_CERTS and not related:
        evidence.append("unrelated_family")
        return "low", evidence
    return "low", evidence


def discover_apex(http: Http, org: OrgConfig) -> tuple[list[ApexCandidate], list[str]]:
    """Return (candidates sorted by confidence then count, source errors)."""
    counts: Counter[str] = Counter()
    errors: list[str] = []

    for name in (org.name, *org.search_names):
        try:
            records = crtsh.org_search(http, name)
        except Exception as exc:  # noqa: BLE001 - report source failures in summary
            errors.append(f"crt.sh org='{name}': {exc}")
            continue
        for record in records:
            if isinstance(record, dict):
                for host in crtsh.hosts_of(record):
                    apex = registrable_apex(host)
                    if apex and not is_infra_apex(apex):
                        counts[apex] += 1

    # Seeds are always candidates even if no certificate matched.
    for seed in org.seed_domains:
        counts.setdefault(seed, 0)
    if not counts:
        return [], errors

    total = sum(counts.values())
    ranked = counts.most_common()
    top_apex = ranked[0][0]
    at = timestamp_now()
    seed_labels = frozenset(main_label(s) for s in org.seed_domains if main_label(s))

    candidates = []
    for apex, count in ranked:
        confidence, evidence = _confidence(
            apex, count, total, apex == top_apex, org, seed_labels
        )
        candidates.append(
            ApexCandidate(
                org_id=org.org_id,
                org_type=org.org_type,
                apex=apex,
                confidence=confidence,
                cert_count=count,
                evidence=tuple(evidence),
                source="crt.sh",
                discovered_at=at,
            )
        )

    candidates.sort(key=lambda c: (CONFIDENCE_ORDER[c.confidence], -c.cert_count))
    return candidates, errors
