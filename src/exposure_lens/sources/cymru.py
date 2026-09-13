"""IP -> ASN mapping via Team Cymru's bulk whois service (whois.cymru.com:43).

One TCP connection resolves every IP at once, off the HTTP request budget.
"""
from __future__ import annotations

import socket

_HOST = ("whois.cymru.com", 43)


def _is_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def parse_bulk(text: str) -> dict[str, str]:
    """Parse verbose bulk output rows ('AS | IP | prefix | ...') into {ip: ASn}."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        cols = [c.strip() for c in line.split("|")]
        if len(cols) >= 2 and cols[0][:1].isdigit() and _is_ipv4(cols[1]):
            result[cols[1]] = f"AS{cols[0]}"
    return result


def annotate(ips: set[str] | list[str], *, timeout: float = 20.0) -> dict[str, str]:
    """Map each IPv4 to its origin ASN in one query; unknowns map to ""."""
    targets = [ip for ip in ips if _is_ipv4(ip)]
    if not targets:
        return {}
    # Team Cymru bulk mode needs CRLF lines and no half-close; "end" ends input.
    query = ("begin\r\nverbose\r\n" + "\r\n".join(targets) + "\r\nend\r\n").encode()
    try:
        with socket.create_connection(_HOST, timeout=timeout) as sock:
            sock.sendall(query)
            buf = bytearray()
            while chunk := sock.recv(8192):
                buf.extend(chunk)
    except OSError:
        return {ip: "" for ip in targets}
    result = parse_bulk(buf.decode("utf-8", errors="replace"))
    for ip in targets:
        result.setdefault(ip, "")
    return result
