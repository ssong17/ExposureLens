"""IP -> ASN mapping via Team Cymru's DNS service (over dns.google DoH).

A TXT query for ``<reversed-ip>.origin.asn.cymru.com`` returns
``"ASN | prefix | country | registry | date"``.
"""
from __future__ import annotations

from ..core.net import Http


def asn_of(http: Http, ip: str) -> str:
    """Return the origin ASN of an IPv4 address (e.g. "AS23576"), or ""."""
    octets = ip.split(".")
    if len(octets) != 4:
        return ""  # IPv6 not supported yet
    name = ".".join(reversed(octets)) + ".origin.asn.cymru.com"
    try:
        data = http.get_json(f"https://dns.google/resolve?name={name}&type=TXT")
    except Exception:  # noqa: BLE001 - ASN is best-effort enrichment
        return ""
    for answer in data.get("Answer", []) if isinstance(data, dict) else []:
        txt = str(answer.get("data", "")).strip('"')
        first = txt.split("|", 1)[0].strip().split()
        if first and first[0].isdigit():
            return f"AS{first[0]}"
    return ""


def annotate(http: Http, ips: set[str]) -> dict[str, str]:
    """Map each unique IP to its ASN (best-effort)."""
    return {ip: asn_of(http, ip) for ip in ips if ip}
