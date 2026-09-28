"""Shared data records and orderings for the pipeline.

The severity/confidence orderings live here because every stage ranks by them;
keeping one copy is what stops `scan`, `inspect` and `verify` from drifting apart.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal

Confidence = Literal["high", "medium", "low"]
AssetType = Literal["apex", "subdomain", "endpoint"]
Severity = Literal["critical", "high", "medium", "low"]

# Single source of truth for ranking. Lower number = more severe / more trusted.
SEVERITY_LEVELS: tuple[str, ...] = ("critical", "high", "medium", "low")
SEVERITY_ORDER: dict[str, int] = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
CONFIDENCE_LEVELS: tuple[str, ...] = ("high", "medium", "low")
CONFIDENCE_ORDER: dict[str, int] = {c: i for i, c in enumerate(CONFIDENCE_LEVELS)}

# One notch down, used when evidence is weaker than the rule assumes (a host that
# no longer resolves, a service on an IP shared with other tenants).
SEVERITY_DOWNGRADE: dict[str, str] = {
    "critical": "high", "high": "medium", "medium": "low", "low": "low",
}


def severity_rank(severity: str) -> int:
    """Rank an arbitrary severity string, treating anything unknown as lowest."""
    return SEVERITY_ORDER.get(severity, len(SEVERITY_LEVELS))


def confidence_rank(confidence: str) -> int:
    """Rank an apex confidence, treating anything unknown as least trusted."""
    return CONFIDENCE_ORDER.get(confidence, len(CONFIDENCE_LEVELS))


def downgrade(severity: str) -> str:
    return SEVERITY_DOWNGRADE.get(severity, severity)


@dataclass(frozen=True)
class ApexCandidate:
    org_id: str
    org_type: str
    apex: str
    confidence: Confidence
    cert_count: int
    evidence: tuple[str, ...]
    source: str
    discovered_at: str

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["evidence"] = list(self.evidence)
        return data


@dataclass(frozen=True)
class Asset:
    record_id: str
    org_id: str
    apex: str
    apex_confidence: Confidence
    asset_type: AssetType
    host: str
    source: str
    discovered_at: str
    # Display name of the owning organization, stamped at collection time so a
    # JSONL row says whose asset it is without the reader holding config.toml.
    org_name: str = ""
    url: str = ""
    resolved_ip: str = ""
    asn: str = ""
    # "current" = a present-tense source saw it (urlscan recently / host resolves);
    # "archived" = only a past index (Wayback) knows it. Separates "still there"
    # from "was there once".
    freshness: str = ""
    last_seen: str = ""  # date a current source last observed it (urlscan), else ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    org_id: str
    asset_ref: str
    severity: Severity
    category: str
    rule: str
    host: str
    url: str  # full, directly-openable URL (scheme+host+path)
    evidence: str
    discovered_at: str
    org_name: str = ""  # owning organization's display name, carried from the asset
    path: str = ""  # URL path component ("/" for a host-level finding)
    # Populated by `probe` (live pass); empty for offline `scan`.
    status: str = ""  # HTTP status observed, or "" when not probed
    source: str = ""  # "scan" | "fetch-body" | "verify-confirmed" | "shodan-internetdb" ...
    freshness: str = ""  # "current" | "archived" — was the underlying asset live now?

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


# Category reserved for reachability rows. It is an asset property, not an
# exposure, so reports separate it out instead of ranking it alongside findings.
LIVENESS_CATEGORY = "liveness"


def is_liveness(finding) -> bool:
    """True for a reachability row (dataclass or dict)."""
    category = (
        finding.get("category", "")
        if isinstance(finding, dict)
        else getattr(finding, "category", "")
    )
    return category == LIVENESS_CATEGORY


class FindingIds:
    """Run-wide unique finding-id allocator.

    Each stage used to number its own findings from 1 with its own prefix, so a
    probe run that did both body inspection and verification emitted
    ``V_<date>_000001`` twice (inspection's liveness row and verification's) and
    ``I_<date>_...`` twice again. One allocator shared by every stage in a run
    removes the whole class of collision.
    """

    def __init__(self, prefix: str, date: str | None = None) -> None:
        self.prefix = prefix
        self.date = date or run_date()
        self._issued = 0

    def __call__(self) -> str:
        self._issued += 1
        return f"{self.prefix}_{self.date}_{self._issued:06d}"

    @property
    def issued(self) -> int:
        return self._issued


def timestamp_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def run_date() -> str:
    return datetime.now().astimezone().strftime("%Y%m%d")


def run_time() -> str:
    """HHMMSS, used to prefix output files within a day's directory."""
    return datetime.now().astimezone().strftime("%H%M%S")
