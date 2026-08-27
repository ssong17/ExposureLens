from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from .models import Candidate
from .urltools import is_static_asset

HIGH_HOST_TERMS = {
    "admin",
    "api",
    "dev",
    "developer",
    "grafana",
    "internal",
    "jenkins",
    "kafka",
    "kibana",
    "n8n",
    "qa",
    "sandbox",
    "stage",
    "staging",
    "stg",
    "test",
}
HIGH_PATH_TERMS = {
    ".env",
    "api-docs",
    "backup",
    "config",
    "graphql",
    "openapi",
    "swagger",
}
LOW_HOST_TERMS = {"blog", "golf", "news"}
LOW_PATH_TERMS = {
    "article",
    "media",
    "news",
    "photo",
    "press",
    "robots.txt",
    "story",
    "webzine",
}


@dataclass(frozen=True)
class AnalysisCandidate:
    canonical_key: str
    representative_url: str
    priority: str
    priority_reasons: list[str]
    variant_count: int
    observed_urls: list[str]
    raw_candidate_ids: list[str]
    discovery_methods: list[str]
    content_hints: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def canonical_url_key(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = parts.path.rstrip("/").lower() or "/"
    return f"{host}{path}"


def build_analysis_candidates(
    raw_candidates: list[Candidate],
) -> tuple[list[AnalysisCandidate], dict[str, int]]:
    groups: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in raw_candidates:
        groups[canonical_url_key(candidate.target_url)].append(candidate)

    results: list[AnalysisCandidate] = []
    priority_counts = {"high": 0, "medium": 0, "low": 0}
    for canonical_key, variants in groups.items():
        representative = min(variants, key=_representative_score)
        priority, reasons = classify_priority(representative.target_url)
        priority_counts[priority] += 1
        if priority == "low":
            continue
        results.append(
            AnalysisCandidate(
                canonical_key=canonical_key,
                representative_url=representative.target_url,
                priority=priority,
                priority_reasons=reasons,
                variant_count=len(variants),
                observed_urls=sorted({item.target_url for item in variants}),
                raw_candidate_ids=[item.candidate_id for item in variants],
                discovery_methods=sorted(
                    {item.discovery_method for item in variants}
                ),
                content_hints=sorted({item.content_hint for item in variants}),
            )
        )
    results.sort(
        key=lambda item: (
            0 if item.priority == "high" else 1,
            item.canonical_key,
        )
    )
    return results, priority_counts


def classify_priority(url: str) -> tuple[str, list[str]]:
    parts = urlsplit(url)
    host_labels = set((parts.hostname or "").lower().split("."))
    path_tokens = {
        token
        for token in parts.path.lower().replace("_", "-").split("/")
        if token
    }

    high_host_matches = sorted(host_labels & HIGH_HOST_TERMS)
    high_path_matches = sorted(
        term for term in HIGH_PATH_TERMS if term in parts.path.lower()
    )
    if high_host_matches or high_path_matches:
        reasons = [f"host:{term}" for term in high_host_matches]
        reasons.extend(f"path:{term}" for term in high_path_matches)
        return "high", reasons

    low_host_matches = sorted(host_labels & LOW_HOST_TERMS)
    low_path_matches = sorted(
        term for term in LOW_PATH_TERMS if term in path_tokens
    )
    if is_static_asset(url) or low_host_matches or low_path_matches:
        reasons = [f"host:{term}" for term in low_host_matches]
        reasons.extend(f"path:{term}" for term in low_path_matches)
        if is_static_asset(url):
            reasons.append("static_asset")
        return "low", reasons
    return "medium", ["official_asset"]


def _representative_score(candidate: Candidate) -> tuple[int, int, int, str]:
    parts = urlsplit(candidate.target_url)
    return (
        0 if parts.scheme == "https" else 1,
        0 if not (parts.hostname or "").startswith("www.") else 1,
        0 if not parts.query else 1,
        candidate.target_url,
    )
