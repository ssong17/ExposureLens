"""crt.sh (Certificate Transparency) adapter.

Organization search (``?O=``) matches the certificate subject Organization and
is used for apex discovery; the domain lives in ``common_name``. Domain search
(``?q=%25.apex``) enumerates subdomains under a confirmed apex.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from ..core.net import Http

_HOSTISH = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9])?)+$"
)


def _clean(token: str) -> str:
    return token.strip().lower().removeprefix("*.").strip(".")


def hosts_of(record: dict[str, Any]) -> set[str]:
    """Extract hostnames from a crt.sh record, ignoring org-name strings."""
    hosts: set[str] = set()
    for field in ("common_name", "name_value"):
        for line in str(record.get(field) or "").splitlines():
            host = _clean(line)
            if host and " " not in host and "@" not in host and _HOSTISH.match(host):
                hosts.add(host)
    return hosts


def org_search(http: Http, org_name: str) -> list[dict[str, Any]]:
    data = http.get_json(f"https://crt.sh/?O={quote(org_name)}&output=json")
    return data if isinstance(data, list) else []


def domain_search(http: Http, apex: str) -> set[str]:
    data = http.get_json(f"https://crt.sh/?q=%25.{quote(apex)}&output=json")
    hosts: set[str] = set()
    if isinstance(data, list):
        for record in data:
            if isinstance(record, dict):
                hosts |= hosts_of(record)
    return {h for h in hosts if h == apex or h.endswith(f".{apex}")}
