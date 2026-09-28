"""Shodan InternetDB adapter — free, keyless, passive view of CURRENT exposure.

``https://internetdb.shodan.io/<ip>`` returns what Shodan's own scanners last saw
on an IP: open ports, hostnames, services. Reading it never touches
the target (Shodan already scanned it), and unlike a web archive it reflects the
present state, not a past snapshot. IPs with no data return 404 -> None.
"""
from __future__ import annotations

from typing import Any
from urllib.error import HTTPError

from ..core.net import Http


def internetdb(http: Http, ip: str) -> dict[str, Any] | None:
    """Return the InternetDB record for an IP, or None if it has no data.

    Only a 404 means "no data". Any other failure is raised: treating a timeout
    as "nothing open" would silently drop the IP, and a resumed scan would then
    never re-ask for it.
    """
    try:
        data = http.get_json(f"https://internetdb.shodan.io/{ip}")
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return data if isinstance(data, dict) else None
