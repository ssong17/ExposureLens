"""Response-body fetchers for the body-reading passes (``scan.bodyscan``).

Two strategies, both read-only:

- ``wayback_body``  reads the archived snapshot from web.archive.org (the `scan`
  archived-body pass): the target is never contacted, only the Internet Archive.
  The ``id_`` modifier returns the original bytes without the Wayback toolbar.
- ``fetch_body``    issues exactly one GET to the target itself (the `probe`
  pass). This touches the target, so it is gated to high-confidence apexes only.
  Redirects are not followed, so the raw status is preserved.

Neither verifies a credential or sends a payload; they retrieve a body so the
content rules can read it.
"""
from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

from ..core.net import Http

# A timestamp far in the future redirects to the most recent snapshot.
_SNAPSHOT = "https://web.archive.org/web/2999id_/{url}"


# Bodies that cannot hold text secrets are not worth a rule pass.
_SKIP_CT = ("image/", "video/", "audio/", "font/", "application/pdf")


def _is_textual(content_type: str) -> bool:
    ct = content_type.lower()
    return not any(ct.startswith(p) or p in ct for p in _SKIP_CT)


def wayback_body(http: Http, url: str) -> tuple[int, str]:
    """Return (200, snapshot_text) or (0, '') when no usable snapshot exists."""
    snapshot = _SNAPSHOT.format(url=quote(url, safe=":/?&=%"))
    try:
        text, content_type = http.get_text(snapshot, limit=http.max_body_bytes)
    except Exception:  # noqa: BLE001 - a missing snapshot is not fatal
        return 0, ""
    if not text or not _is_textual(content_type):
        return 0, ""
    return 200, text


def fetch_body(http: Http, url: str) -> tuple[int, str]:
    """One GET to the target; return (status, body_text). status 0 = unreachable."""
    status, text, content_type, _location = http.probe(url)
    if not _is_textual(content_type):
        return status, ""
    return status, text


def home_body(http: Http, url: str) -> tuple[int, int]:
    """GET the host ROOT ("/") — a real, non-guessed path — as a baseline.

    Returns ``(status, body_length)``. An SPA / catch-all router serves this
    same index page for every route, so when a discovered path returns a body
    of the same size it is the index fallback, not that path's own content.
    Using "/" (not a fabricated path) keeps the "never guess paths" guarantee.
    """
    parts = urlsplit(url)
    root = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
    status, text, content_type, _loc = http.probe(root)
    if not _is_textual(content_type):
        return status, 0
    return status, len(text)
