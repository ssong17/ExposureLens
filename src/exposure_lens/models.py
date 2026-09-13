"""Shared data records for the collection pipeline."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal

Confidence = Literal["high", "medium", "low"]
AssetType = Literal["apex", "subdomain", "ip", "endpoint"]


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
    resolved_ip: str = ""
    asn: str = ""
    in_scope: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def timestamp_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def run_date() -> str:
    return datetime.now().astimezone().strftime("%Y%m%d")
