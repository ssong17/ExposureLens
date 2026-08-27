from __future__ import annotations

from html.parser import HTMLParser
import xml.etree.ElementTree as ET

from .models import DiscoveredLink
from .urltools import content_hint, normalize_url


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag in {"a", "link"} and values.get("href"):
            self.links.append(values["href"] or "")
        elif tag in {"script", "img", "iframe", "source"} and values.get("src"):
            self.links.append(values["src"] or "")


def discover_html(source_url: str, body: bytes) -> list[DiscoveredLink]:
    parser = LinkParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    result: list[DiscoveredLink] = []
    for raw_url in parser.links:
        try:
            target = normalize_url(raw_url, source_url)
        except (ValueError, UnicodeError):
            continue
        result.append(
            DiscoveredLink(
                source_url=source_url,
                target_url=target,
                discovery_method="html_link",
                content_hint=content_hint(target),
            )
        )
    return result


def discover_sitemap(source_url: str, body: bytes) -> list[DiscoveredLink]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    result: list[DiscoveredLink] = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].lower() != "loc" or not element.text:
            continue
        try:
            target = normalize_url(element.text.strip(), source_url)
        except ValueError:
            continue
        result.append(
            DiscoveredLink(
                source_url=source_url,
                target_url=target,
                discovery_method="sitemap",
                content_hint=content_hint(target),
            )
        )
    return result


def discover_robots(source_url: str, body: bytes) -> list[DiscoveredLink]:
    result: list[DiscoveredLink] = []
    for line in body.decode("utf-8", errors="replace").splitlines():
        key, separator, value = line.partition(":")
        if not separator or key.strip().lower() != "sitemap":
            continue
        try:
            target = normalize_url(value.strip(), source_url)
        except ValueError:
            continue
        result.append(
            DiscoveredLink(
                source_url=source_url,
                target_url=target,
                discovery_method="robots_sitemap",
                content_hint="xml",
            )
        )
    return result
