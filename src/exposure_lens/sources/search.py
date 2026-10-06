"""Search-engine discovery (opt-in, ``--search``).

Finds URLs a search engine has indexed but the archive/CT sources have not — the
``site:x "관리자"`` case: admin/CMS pages Google knows but Wayback does not.

Keyless by default: credentials are read ONLY from environment variables, and
with none set this returns nothing (the stage is simply skipped). Two providers,
matching the vibecodding_scanner project's approach:

- Google : ``GOOGLE_API_KEY`` + ``GOOGLE_CSE_ID`` (Custom Search) — key in URL.
- Brave  : ``BRAVE_SEARCH_API_KEY`` — sent as a request header.

Reads only the search API (a third party), never the target — like the other
collect sources. Returns observations shaped like the other collectors
(``[{"url", "seen", "status"}]``) so the collector folds them in unchanged.
"""
from __future__ import annotations

import json
import os
import re
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from ..core.net import Http

# Any Hangul syllable — the cheap, request-free signal that a result page is
# operated for a Korean audience (title/snippet already come back with the
# search result, so no extra fetch and nothing touches the target).
_HANGUL = re.compile(r"[가-힣]")
# Korean country-code TLDs (.kr and its second-levels like co.kr/go.kr/ac.kr).
_KR_TLD = re.compile(r"\.kr$", re.IGNORECASE)


def _is_kr_target(url: str, text: str) -> bool:
    """True when a search hit looks operated for a Korean audience.

    Two no-touch signals, matching the brief ("페이지 언어가 한국이든, .kr TLD 등"):
    a Korean ccTLD host, or Hangul in the result's own title/snippet. Everything
    else is treated as a non-Korean target and dropped by ``fetch_observations``
    — the search operator (site:) can surface a global CDN/mirror under an apex,
    and those are out of scope for a Korea-focused run.
    """
    host = (urlsplit(url).hostname or "").lower()
    if _KR_TLD.search(host):
        return True
    return bool(_HANGUL.search(text))

# Default query templates run per apex; {apex} is substituted. Tuned for the
# admin/CMS surface the archive misses; the Korean term catches localized
# panels. Overridable per run (see ``_as_query`` / config ``search_queries`` /
# CLI ``--search-query``).
DEFAULT_QUERIES = (
    # admin / auth surface
    "site:{apex} (admin OR login OR 로그인 OR 관리자)",
    "site:{apex} inurl:admin",
    "site:{apex} inurl:login",
    # file / directory exposure (classic dorks, high yield)
    'site:{apex} intitle:"index of"',
    "site:{apex} filetype:sql",
    "site:{apex} (inurl:.env OR filetype:env OR filetype:log)",
    "site:{apex} (filetype:bak OR inurl:backup)",
    # PII-bearing documents
    "site:{apex} (filetype:xlsx OR filetype:csv)",
)


def _as_query(value: str, apex: str) -> str:
    """Turn a configured value into a concrete search query.

    A value with ``{apex}`` is a full template used verbatim; anything else is
    a bare keyword wrapped as ``site:<apex> "<keyword>"`` — the exact
    ``site:apex "키워드"`` shape, so operators can just pass "관리자" or "백업".
    """
    if "{apex}" in value:
        return value.format(apex=apex)
    return f'site:{apex} "{value}"'


def _google(http: Http, query: str, limit: int) -> list[tuple[str, str]]:
    """Return [(url, title+snippet)] from Google CSE, or [] without keys."""
    key, engine = os.getenv("GOOGLE_API_KEY"), os.getenv("GOOGLE_CSE_ID")
    if not key or not engine:
        return []
    url = ("https://www.googleapis.com/customsearch/v1?"
           + urlencode({"key": key, "cx": engine, "q": query, "num": min(10, limit)}))
    try:
        data = http.get_json(url)  # key is in the URL, no custom header needed
    except Exception:  # noqa: BLE001 - a search failure must not abort collection
        return []
    items = (data or {}).get("items", []) if isinstance(data, dict) else []
    return [
        (r["link"], f"{r.get('title', '')} {r.get('snippet', '')}")
        for r in items if isinstance(r, dict) and r.get("link")
    ]


def _brave(http: Http, query: str, limit: int) -> list[tuple[str, str]]:
    """Return [(url, title+description)] from Brave, or [] without a key."""
    key = os.getenv("BRAVE_SEARCH_API_KEY")
    if not key:
        return []
    url = ("https://api.search.brave.com/res/v1/web/search?"
           + urlencode({"q": query, "count": min(20, limit)}))
    # Brave needs an auth header, which Http.get_json does not send, so issue a
    # small direct request (still just reading the search API, never the target).
    req = Request(url, headers={
        "X-Subscription-Token": key, "User-Agent": http.user_agent, "Accept": "application/json",
    })
    try:
        with urlopen(req, timeout=http.timeout) as resp:
            data = json.loads(resp.read(http.max_bytes).decode("utf-8", "replace"))
    except (URLError, TimeoutError, ValueError, OSError):
        return []
    results = (data or {}).get("web", {}).get("results", []) if isinstance(data, dict) else []
    return [
        (r["url"], f"{r.get('title', '')} {r.get('description', '')}")
        for r in results if isinstance(r, dict) and r.get("url")
    ]


def fetch_observations(
    http: Http, apex: str, limit: int = 20, *, provider: str = "auto",
    queries: "tuple[str, ...] | list[str] | None" = None,
    kr_only: bool = True,
) -> list[dict]:
    """Return [{url, seen, status}] from the search provider, or [] without keys.

    ``provider``: 'google', 'brave', or 'auto' (use whichever has credentials).
    ``queries``: templates/keywords to run (default ``DEFAULT_QUERIES``); each is
    resolved by ``_as_query`` so a bare keyword becomes ``site:apex "keyword"``.
    ``kr_only`` (default): keep only hits that look operated for a Korean
    audience (``_is_kr_target`` — .kr host or Hangul in the title/snippet). The
    ``site:`` operator can surface non-Korean mirrors/CDNs under an apex, and
    this run is Korea-focused, so those are dropped before they enter collection.
    """
    templates = tuple(queries) if queries else DEFAULT_QUERIES
    providers = ["google", "brave"] if provider == "auto" else [provider]
    hits: list[tuple[str, str]] = []
    for name in providers:
        fn = {"google": _google, "brave": _brave}.get(name)
        if fn is None:
            continue
        for template in templates:
            if len(hits) >= limit:
                break
            hits.extend(fn(http, _as_query(template, apex), limit - len(hits)))
        if hits:
            break  # one working provider is enough
    seen: set[str] = set()
    out: list[dict] = []
    for u, text in hits:
        if u in seen:
            continue
        if kr_only and not _is_kr_target(u, text):
            continue
        seen.add(u)
        out.append({"url": u, "seen": "", "status": ""})
    return out[:limit]
