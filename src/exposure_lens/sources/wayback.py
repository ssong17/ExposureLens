"""Wayback Machine CDX adapter: archived URLs under an apex, or under one host.

Yields endpoint URLs (which the scanner consumes) and also serves as a backup
subdomain source when crt.sh is unavailable.

CDX returns rows sorted by SURT key (reversed host, then path), so a query that
hits ``limit`` is not a sample: it is the alphabetically-first hosts in full and
nothing of the rest. The collector detects that and re-queries per host.
"""
from __future__ import annotations

from urllib.parse import quote

from ..core.net import Http

_CDX = (
    "https://web.archive.org/cdx/search/cdx?url={pattern}&output=json"
    "&fl=original&collapse=urlkey&filter=statuscode:200&limit={limit}"
)


def fetch_urls(http: Http, apex: str, limit: int = 1000) -> list[str]:
    """URLs under the apex and every subdomain (``*.apex``), in CDX order."""
    return _fetch(http, f"*.{apex}/*", limit)


def fetch_host_urls(http: Http, host: str, limit: int = 1000) -> list[str]:
    """URLs under exactly this host (no subdomains), in CDX order."""
    return _fetch(http, f"{host}/*", limit)


def _fetch(http: Http, pattern: str, limit: int) -> list[str]:
    data = http.get_json(_CDX.format(pattern=quote(pattern), limit=limit))
    if not isinstance(data, list) or len(data) < 2:
        return []
    return [row[0] for row in data[1:] if isinstance(row, list) and row]


def as_observations(urls: list[str]) -> list[dict]:
    """URLs as observations. Wayback is an archive, so ``seen`` stays empty —
    the collector treats these as historical unless a current source confirms."""
    return [{"url": u, "seen": "", "status": ""} for u in urls]


def fetch_observations(http: Http, apex: str, limit: int = 1000) -> list[dict]:
    return as_observations(fetch_urls(http, apex, limit))
