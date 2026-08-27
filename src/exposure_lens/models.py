from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    track: Literal["DIRECT", "PASSIVE"]
    company_name: str
    source_platform: str
    source_url: str
    target_platform: str
    target_url: str
    discovery_method: str
    matched_indicator: str
    discovered_at: str
    content_hint: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class DiscoveredLink:
    source_url: str
    target_url: str
    discovery_method: str
    content_hint: str


def timestamp_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")
