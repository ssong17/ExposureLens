from __future__ import annotations

import ipaddress
import socket
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


TRACKING_PARAMS = frozenset({"fbclid", "gclid", "mc_cid", "mc_eid"})
KNOWN_FILE_SUFFIXES = frozenset(
    {
        "csv",
        "css",
        "doc",
        "docx",
        "eot",
        "gif",
        "ico",
        "jpeg",
        "jpg",
        "js",
        "json",
        "m4a",
        "mov",
        "mp3",
        "mp4",
        "ogg",
        "pdf",
        "png",
        "ppt",
        "pptx",
        "svg",
        "txt",
        "webm",
        "webp",
        "woff",
        "woff2",
        "xls",
        "xlsx",
        "xml",
    }
)
STATIC_ASSET_SUFFIXES = frozenset(
    {
        "css",
        "eot",
        "gif",
        "ico",
        "jpeg",
        "jpg",
        "m4a",
        "mov",
        "mp3",
        "mp4",
        "ogg",
        "png",
        "svg",
        "webm",
        "webp",
        "woff",
        "woff2",
    }
)


def normalize_url(url: str, base_url: str | None = None) -> str:
    absolute = urljoin(base_url, url) if base_url else url
    parts = urlsplit(absolute)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("HTTP(S) URL만 허용합니다.")
    if not parts.hostname or parts.username or parts.password:
        raise ValueError("호스트가 없거나 사용자정보가 포함된 URL은 허용하지 않습니다.")

    scheme = parts.scheme.lower()
    host = parts.hostname.lower().rstrip(".")
    port = parts.port
    uses_default_port = (scheme, port) in {("http", 80), ("https", 443)}
    if port and not uses_default_port:
        netloc = f"{host}:{port}"
    else:
        netloc = host

    query_items = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if not key.lower().startswith("utm_") and key.lower() not in TRACKING_PARAMS
    ]
    query = urlencode(sorted(query_items))
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, query, ""))


def host_allowed(url: str, domains: tuple[str, ...]) -> bool:
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return any(host == domain or host.endswith(f".{domain}") for domain in domains)


def ensure_public_host(url: str) -> None:
    host = urlsplit(url).hostname
    if not host or host.lower() == "localhost" or host.lower().endswith(".local"):
        raise ValueError("로컬 호스트는 요청하지 않습니다.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise ValueError(f"호스트를 확인할 수 없습니다: {host}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError(f"공인 IP가 아닌 주소는 요청하지 않습니다: {address}")


def content_hint(url: str, content_type: str = "") -> str:
    path = urlsplit(url).path.lower()
    suffix = path.rsplit("/", 1)[-1].rsplit(".", 1)
    if len(suffix) == 2 and suffix[1] in KNOWN_FILE_SUFFIXES:
        return suffix[1]
    lowered = content_type.lower()
    if "html" in lowered:
        return "html"
    if "javascript" in lowered:
        return "js"
    if "json" in lowered:
        return "json"
    if "xml" in lowered:
        return "xml"
    if "pdf" in lowered:
        return "pdf"
    return "unknown"


def is_static_asset(url: str, hint: str | None = None) -> bool:
    asset_hint = hint or content_hint(url)
    return asset_hint in STATIC_ASSET_SUFFIXES


def target_platform(url: str, official_domains: tuple[str, ...]) -> str:
    if host_allowed(url, official_domains):
        return "company_web"
    host = (urlsplit(url).hostname or "").lower()
    if host == "github.com" or host.endswith(".github.com"):
        return "github"
    if host == "gitlab.com" or host.endswith(".gitlab.com"):
        return "gitlab"
    if host == "bitbucket.org" or host.endswith(".bitbucket.org"):
        return "bitbucket"
    return "external_web"
