"""urlscan.io adapter: recently-observed URLs for a domain, with recency.

The search API (``/api/v1/search/?q=domain:<apex>``) returns URLs from scans
people ran against the domain — recent, real observations rather than a years-old
archive. Each result carries WHEN it was scanned and the HTTP status seen, so it
doubles as a present-tense liveness signal. Keyless (rate-limited) and passive:
it reads urlscan's database, never the target.

``size`` is capped at 100 per page by the API, so a larger limit is walked with
``search_after`` (the sort key of the last row) rather than silently truncated.
"""
from __future__ import annotations

from urllib.parse import quote

from ..core.net import Http

PAGE_SIZE = 100
_MAX_PAGES = 20  # hard stop so a pathological domain cannot loop forever


def _rows(data: dict) -> list[dict]:
    return [r for r in data.get("results", []) if isinstance(r, dict)]


def _observations(row: dict) -> list[dict]:
    """Flatten one result row into observations, de-duplicating page/task URLs."""
    page = row.get("page") or {}
    seen = str((row.get("task") or {}).get("time", ""))[:10]
    status = str(page.get("status", "") or "")
    urls: list[str] = []
    for section in ("page", "task"):
        url = (row.get(section) or {}).get("url", "")
        if url and url not in urls:  # page.url and task.url are usually identical
            urls.append(url)
    return [{"url": u, "seen": seen, "status": status} for u in urls]


def fetch_observations(http: Http, apex: str, limit: int = PAGE_SIZE) -> list[dict]:
    """Return [{url, seen(YYYY-MM-DD), status}] observed for the domain."""
    query = quote(f"domain:{apex}")
    out: list[dict] = []
    search_after = ""

    for _page in range(_MAX_PAGES):
        remaining = limit - len(out)
        if remaining <= 0:
            break
        size = min(PAGE_SIZE, remaining)
        url = f"https://urlscan.io/api/v1/search/?q={query}&size={size}"
        if search_after:
            url += f"&search_after={quote(search_after)}"
        data = http.get_json(url)
        if not isinstance(data, dict):
            break
        rows = _rows(data)
        if not rows:
            break
        for row in rows:
            out.extend(_observations(row))
        # The next page starts after the last row's sort key; without one the
        # API has no more pages to give.
        sort = rows[-1].get("sort")
        if not isinstance(sort, list) or not sort or not data.get("has_more"):
            break
        search_after = ",".join(str(v) for v in sort)

    return out[:limit] if limit else out
