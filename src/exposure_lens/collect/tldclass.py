"""Registrable-apex extraction and TLD classification.

Uses a built-in set of two-level suffixes (focused on Korean public/education
domains) instead of the full Public Suffix List to stay dependency-free.
"""
from __future__ import annotations

# Suffixes whose registrable domain is the last three labels (e.g. snu.ac.kr).
TWO_LEVEL_SUFFIXES = frozenset(
    {
        "co.kr", "go.kr", "ac.kr", "or.kr", "re.kr", "ne.kr", "pe.kr",
        "hs.kr", "ms.kr", "es.kr", "sc.kr", "kg.kr", "mil.kr",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.cn", "edu.cn", "gov.cn",
        "com.au", "edu.au", "gov.au",
        "co.uk", "ac.uk", "gov.uk", "org.uk",
    }
)

# org_type -> TLD classes accepted as ownership evidence.
_EXPECTED_CLASSES: dict[str, frozenset[str]] = {
    "company": frozenset({"company"}),
    "gov": frozenset({"gov"}),
    "school": frozenset({"school", "research"}),
    "nonprofit": frozenset({"nonprofit", "research"}),
    "research": frozenset({"research", "school"}),
    "other": frozenset(),
}

# Third-party infra/CDN apexes that show up via shared certificates.
INFRA_APEXES = frozenset(
    {
        "amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
        "akamai.net", "akamaihd.net", "akamaiedge.net", "edgekey.net",
        "azureedge.net", "windows.net", "trafficmanager.net",
        "googleusercontent.com", "googleapis.com", "gstatic.com",
        "fastly.net", "cloudflare.net", "cloudflaressl.com",
        "github.io", "herokuapp.com", "netlify.app", "vercel.app",
        "wordpress.com", "myshopify.com",
    }
)


def registrable_apex(host: str) -> str:
    """Return the registrable apex of a host, or "" if it has no dot."""
    host = host.strip().lower().strip(".")
    if not host or "." not in host:
        return ""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def main_label(apex: str) -> str:
    """Return the registrable label of an apex (e.g. snu.ac.kr -> 'snu').

    Used to tell whether a candidate apex belongs to the same registrable family
    as a known seed: snu.ac.kr and seoultech.ac.kr share a TLD class but not a
    main label, so the latter is a different institution, not a sibling asset.
    """
    a = apex.strip().lower().strip(".")
    labels = a.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return labels[-3]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels and labels[0] else ""


def tld_class(apex: str) -> str:
    """Classify an apex by ownership type (gov/school/company/...)."""
    a = apex.lower()
    if a.endswith(".mil.kr"):
        return "military"
    if a.endswith(".go.kr") or a.endswith(".gov.kr") or ".gov." in f".{a}.":
        return "gov"
    if (
        a.endswith((".ac.kr", ".hs.kr", ".ms.kr", ".es.kr", ".sc.kr", ".ac.jp", ".ac.uk"))
        or a.endswith(".edu")
        or ".edu." in f".{a}."
    ):
        return "school"
    if a.endswith(".re.kr"):
        return "research"
    if a.endswith(".or.kr") or a.endswith(".org") or ".org." in f".{a}.":
        return "nonprofit"
    if a.endswith((".co.kr", ".kr", ".com", ".net", ".io", ".ai", ".co", ".biz", ".app")):
        return "company"
    return "other"


def expected_classes(org_type: str) -> frozenset[str]:
    return _EXPECTED_CLASSES.get(org_type, frozenset())


def is_infra_apex(apex: str) -> bool:
    return apex.lower() in INFRA_APEXES
