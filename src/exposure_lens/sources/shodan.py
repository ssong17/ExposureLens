"""Shodan InternetDB adapter — free, keyless, passive view of CURRENT exposure.

``https://internetdb.shodan.io/<ip>`` returns what Shodan's own scanners last saw
on an IP: open ports, hostnames, services. Reading it never touches
the target (Shodan already scanned it), and unlike a web archive it reflects the
present state, not a past snapshot. IPs with no data return 404 -> None.
"""
from __future__ import annotations

from typing import Any

from ..core.net import Http


def internetdb(http: Http, ip: str) -> dict[str, Any] | None:
    """Return the InternetDB record for an IP, or None if it has no data."""
    try:
        data = http.get_json(f"https://internetdb.shodan.io/{ip}")
    except Exception:  # noqa: BLE001 - 404 (no data) and transient errors alike
        return None
    return data if isinstance(data, dict) else None
