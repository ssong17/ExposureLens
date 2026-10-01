"""Wayback Machine CDX adapter: archived URLs under an apex.

Yields endpoint URLs (which the scanner consumes) and also serves as a backup
subdomain source when crt.sh is unavailable.

CDX sorts rows by SURT key (reversed host, then path), so a single capped query
returns only the alphabetically-first hosts in full and nothing of the rest —
the back subdomains are lost. The fix is the CDX server's own **pagination**:
ask ``showNumPages`` how many pages the query has, then pull ``page=0..N-1``.
That returns every subdomain's URLs (no cap gap) in N requests, instead of
re-querying each host separately.
"""
from __future__ import annotations

from urllib.parse import quote

from ..core.net import Http

_BASE = "https://web.archive.org/cdx/search/cdx?url={pattern}"
# One page of results (filtered to 200s, exact-dup snapshots collapsed).
_PAGE = (_BASE + "&output=json&fl=original&collapse=urlkey"
         "&filter=statuscode:200&page={page}")
# Page count only — must be requested ALONE (no output=json/fl), or CDX returns
# a malformed body.
_NUMPAGES = _BASE + "&showNumPages=true"


def _num_pages(http: Http, pattern: str) -> int:
    """How many CDX pages this query has (0 = unknown / could not tell)."""
    try:
        text, _ct = http.get_text(_NUMPAGES.format(pattern=quote(pattern)), limit=64)
    except Exception:  # noqa: BLE001 - treated as unknown, caller falls back
        return 0
    head = text.strip().splitlines()[0] if text.strip() else ""
    return int(head) if head.isdigit() else 0


def _page(http: Http, pattern: str, page: int) -> list[str]:
    data = http.get_json(_PAGE.format(pattern=quote(pattern), page=page))
    if not isinstance(data, list) or len(data) < 2:
        return []
    return [row[0] for row in data[1:] if isinstance(row, list) and row]


def _fetch_paged(http: Http, pattern: str, max_pages: int) -> list[str]:
    """All URLs for a CDX pattern via pagination (every subdomain, no cap gap).

    ``max_pages`` (0 = no cap) bounds a pathologically large domain. If the page
    count cannot be read, fall back to a single unpaged query so we still get
    the first page's worth rather than nothing.
    """
    pages = _num_pages(http, pattern)
    if pages <= 0:
        return _page(http, pattern, 0)  # fallback: one unpaged query
    if max_pages:
        pages = min(pages, max_pages)
    urls: list[str] = []
    seen: set[str] = set()
    for p in range(pages):
        for u in _page(http, pattern, p):
            if u not in seen:
                seen.add(u)
                urls.append(u)
    return urls


def fetch_urls(http: Http, apex: str, max_pages: int = 0) -> list[str]:
    """Every archived URL under the apex and all its subdomains (``*.apex``)."""
    return _fetch_paged(http, f"*.{apex}/*", max_pages)


def as_observations(urls: list[str]) -> list[dict]:
    """URLs as observations. Wayback is an archive, so ``seen`` stays empty —
    the collector treats these as historical unless a current source confirms."""
    return [{"url": u, "seen": "", "status": ""} for u in urls]


def fetch_observations(http: Http, apex: str, max_pages: int = 0) -> list[dict]:
    return as_observations(fetch_urls(http, apex, max_pages))
