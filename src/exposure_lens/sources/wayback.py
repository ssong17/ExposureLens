"""Wayback Machine CDX adapter: archived URLs under an apex.

Yields endpoint URLs (which the scanner consumes) and also serves as a backup
subdomain source when crt.sh is unavailable.
"""
from __future__ import annotations

from urllib.parse import quote

from ..core.net import Http

_CDX = (
    "https://web.archive.org/cdx/search/cdx?url={pattern}&output=json"
    "&fl=original&collapse=urlkey&filter=statuscode:200&limit={limit}"
)


def fetch_urls(http: Http, apex: str, limit: int = 1000) -> list[str]:
    pattern = quote(f"*.{apex}/*")
    data = http.get_json(_CDX.format(pattern=pattern, limit=limit))
    if not isinstance(data, list) or len(data) < 2:
        return []
    return [row[0] for row in data[1:] if isinstance(row, list) and row]


def fetch_observations(http: Http, apex: str, limit: int = 1000) -> list[dict]:
    """Same URLs as observations. Wayback is an archive, so ``seen`` stays empty —
    the collector treats these as historical unless a current source confirms."""
    return [{"url": u, "seen": "", "status": ""} for u in fetch_urls(http, apex, limit)]
