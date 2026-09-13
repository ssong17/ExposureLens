"""Rate-limited JSON/HTTP client for public indexes.

All outbound requests go through here so free-tier rate limits are respected:
a minimum interval between requests, bounded retries, a global request cap,
a response-size cap, and a per-URL cache. Only third-party indexes (crt.sh,
dns.google, ...) are queried, never the target's own servers.
"""
from __future__ import annotations

import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class RequestBudgetExceeded(RuntimeError):
    """Raised when the configured request cap is reached."""


class Http:
    def __init__(
        self,
        *,
        user_agent: str,
        interval: float,
        timeout: float,
        max_retries: int,
        max_bytes: int,
        max_requests: int,
    ) -> None:
        self.user_agent = user_agent
        self.interval = interval
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_bytes = max_bytes
        self.max_requests = max_requests
        self.request_count = 0
        self._last_at = 0.0
        self._json_cache: dict[str, Any] = {}

    def get_bytes(self, url: str) -> tuple[bytes, str]:
        if self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(f"request cap {self.max_requests} reached")
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._throttle()
            request = Request(url, headers={"User-Agent": self.user_agent}, method="GET")
            self.request_count += 1
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    body = response.read(self.max_bytes + 1)
                    if len(body) > self.max_bytes:
                        raise ValueError("response exceeds size cap")
                    return body, response.headers.get("Content-Type", "")
            except (HTTPError, URLError, TimeoutError, ValueError) as exc:
                last = exc
                if attempt >= self.max_retries:
                    break
        assert last is not None
        raise last

    def get_json(self, url: str) -> Any:
        """Fetch and parse JSON (or NDJSON), cached per URL."""
        if url in self._json_cache:
            return self._json_cache[url]
        body, content_type = self.get_bytes(url)
        data = self._parse(body.decode("utf-8", errors="replace"), content_type)
        self._json_cache[url] = data
        return data

    @staticmethod
    def _parse(text: str, content_type: str) -> Any:
        if "x-ndjson" in content_type.lower():
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Some endpoints return newline-delimited JSON without the header.
            lines = [line for line in text.splitlines() if line.strip()]
            if lines and lines[0].lstrip()[:1] in "{[" and text.lstrip()[:1] not in "{[":
                return [json.loads(line) for line in lines]
            raise

    def _throttle(self) -> None:
        delay = self.interval - (time.monotonic() - self._last_at)
        if delay > 0:
            time.sleep(delay)
        self._last_at = time.monotonic()
