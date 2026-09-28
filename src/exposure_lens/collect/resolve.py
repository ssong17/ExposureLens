"""Hostname -> IP resolution via the system resolver (off the request budget)."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor


def _first_ipv4(host: str) -> str:
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        # UnicodeError: malformed host (empty/invalid IDNA label) — treat as
        # unresolvable rather than crashing the run.
        return ""
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            return sockaddr[0]
    return infos[0][4][0] if infos else ""


def resolve_hosts(
    hosts: list[str], *, timeout: float = 3.0, workers: int = 20
) -> dict[str, str]:
    """Resolve hosts concurrently; unresolved hosts map to ""."""
    if not hosts:
        return {}
    socket.setdefaulttimeout(timeout)
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            ips = pool.map(_first_ipv4, hosts)
            return dict(zip(hosts, ips))
    finally:
        socket.setdefaulttimeout(None)
