"""Response-body fetchers for `inspect`.

Two strategies, both read-only:

- ``wayback_body``  reads the archived snapshot from web.archive.org. Fully
  passive: the target is never contacted, only the Internet Archive. The
  ``id_`` modifier returns the original bytes without the Wayback toolbar.
- ``fetch_body``    issues exactly one GET to the target itself. This touches
  the target, so `inspect` gates it behind an explicit flag and high-confidence
  apexes only. Redirects are not followed, so the raw status is preserved.

Neither verifies a credential or sends a payload; they retrieve a body so the
content rules can read it.
"""
from __future__ import annotations

from urllib.parse import quote

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
