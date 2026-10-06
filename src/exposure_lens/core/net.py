"""Rate-limited JSON/HTTP client for public indexes.

All outbound requests go through here so free-tier rate limits are respected:
a minimum interval between requests *to the same host*, bounded retries, a global
request cap, a response-size cap, and a bounded per-URL cache.

The interval is per-host on purpose. crt.sh, web.archive.org, urlscan.io and
internetdb.shodan.io enforce their own separate limits, so a single global queue
made every stage wait on unrelated services — a 500-IP Shodan pass alone cost
~17 minutes at a 2s global interval. Politeness to each service is preserved;
the artificial coupling between them is not.
"""
from __future__ import annotations

import json
import time
from collections import OrderedDict
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
    urlopen,
)


class RequestBudgetExceeded(RuntimeError):
    """Raised when the configured request cap is reached."""


class NetworkDown(RuntimeError):
    """Raised after several requests in a row failed to connect at all.

    One unreachable index is a source error, recorded and skipped. Every request
    failing — regardless of host — means OUR connection is gone, and carrying on
    would mark every remaining org/IP as "collected, nothing found". Stopping
    lets the stage checkpoint and a ``--resume`` run pick up where it broke.
    """


# Waits before each retry of a transient failure (seconds). A short first wait
# clears the common single blip fast (crt.sh 502, one 503); the ladder then
# doubles so a real outage still backs off: 2 -> 4 -> 8 -> 16 -> 32.
DEFAULT_RETRY_DELAYS: tuple[float, ...] = (2.0, 4.0, 8.0, 16.0, 32.0)

# Requests in a row (each after exhausting its retries) that failed to connect
# before the network is declared down.
DEFAULT_DOWN_AFTER = 3


# Transient server/network responses worth retrying (crt.sh returns 502/503
# constantly). A 404 is NOT here: it means "no results", so retrying is pointless.
_TRANSIENT_STATUS = frozenset({429, 500, 502, 503, 504})

# Parsed-JSON cache bound. A Wayback CDX page for one apex is thousands of rows;
# with 25 apexes per org and several orgs per run an unbounded dict grew for the
# whole process. Recent entries are what dedupe actually needs.
DEFAULT_CACHE_ENTRIES = 128


class _NoRedirect(HTTPRedirectHandler):
    """Surface 3xx as an HTTPError instead of following it.

    `probe` needs the raw status of a URL to tell an open page (2xx) from one
    that challenges or redirects to a login (301/302/401/403); following the hop
    would hide exactly that signal.
    """

    def redirect_request(self, *args, **kwargs):  # noqa: D401, ANN002, ANN003
        return None


def _is_connect_failure(exc: Exception) -> bool:
    if isinstance(exc, HTTPError):
        return False
    if isinstance(exc, ConnectionError):
        return True
    if isinstance(exc, URLError):
        return not isinstance(exc.reason, TimeoutError)
    return False


def request_host(url: str) -> str:
    """Throttle bucket for a URL: its hostname, lowercased ('' when unparseable)."""
    return (urlsplit(url).hostname or "").lower()


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
        max_body_bytes: int | None = None,
        retry_delays: "tuple[float, ...] | list[float]" = DEFAULT_RETRY_DELAYS,
        down_after: int = DEFAULT_DOWN_AFTER,
        cache_entries: int = DEFAULT_CACHE_ENTRIES,
        on_retry: "Callable[[str], None] | None" = None,
    ) -> None:
        self.user_agent = user_agent
        self.interval = interval
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_bytes = max_bytes
        # Bodies read for content rules are capped far lower than index
        # responses: a secret is in the first few hundred KB, and running every
        # regex over a multi-megabyte bundle costs more than it finds.
        self.max_body_bytes = min(max_body_bytes or max_bytes, max_bytes)
        self.max_requests = max_requests
        self.retry_delays = tuple(retry_delays) or (0.0,)
        self.down_after = down_after
        self._connect_failures = 0  # consecutive calls that never connected
        # Every call that never connected, ever. Callers compare it before and
        # after a unit of work to tell "done, nothing found" from "the link
        # dropped while doing it" (which must be redone on resume).
        self.connect_failure_total = 0
        self.cache_entries = max(0, cache_entries)
        self._on_retry = on_retry
        self.request_count = 0
        # host -> monotonic time of that host's last request.
        self._last_at: dict[str, float] = {}
        self._json_cache: "OrderedDict[str, Any]" = OrderedDict()

    def get_bytes(self, url: str) -> tuple[bytes, str]:
        if self.max_requests and self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(f"request cap {self.max_requests} reached")
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._throttle(url)
            request = Request(url, headers={"User-Agent": self.user_agent}, method="GET")
            self.request_count += 1
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    body = response.read(self.max_bytes + 1)
                    if len(body) > self.max_bytes:
                        raise ValueError("response exceeds size cap")
                    self._connect_failures = 0
                    return body, response.headers.get("Content-Type", "")
            except ValueError:
                raise  # size cap breach: a real error, not worth retrying
            except HTTPError as exc:
                last = exc
                if exc.code not in _TRANSIENT_STATUS or attempt >= self.max_retries:
                    break  # 404 etc., or out of retries
            except (URLError, TimeoutError, ConnectionError) as exc:
                last = exc  # transient network failure (incl. reset mid-read)
                if attempt >= self.max_retries:
                    break
            # Transient failure with retries left: wait and retry the SAME query
            # instead of skipping it, so a crt.sh 502 blip does not silently
            # drop coverage.
            delay = self.retry_delay(attempt)
            if self._on_retry:
                self._on_retry(
                    f"retry {attempt + 1}/{self.max_retries} after {delay:.0f}s "
                    f"({last}): {url}"
                )
            time.sleep(delay)
        assert last is not None
        self._note_failure(last)
        raise last

    def retry_delay(self, attempt: int) -> float:
        """Wait before retry ``attempt + 1``; past the ladder, its last rung."""
        return self.retry_delays[min(attempt, len(self.retry_delays) - 1)]

    def _note_failure(self, exc: Exception) -> None:
        """Count calls that never reached a server; raise when the link is gone.

        Only a failure to CONNECT counts (DNS failure, refused, unreachable,
        reset). An HTTPError (502, 429, 404) is a server that answered, and a
        read timeout is usually crt.sh being slow on a big query — neither says
        our link is down, so both reset the count just like a success does.
        """
        if not _is_connect_failure(exc):
            self._connect_failures = 0
            return
        self._connect_failures += 1
        self.connect_failure_total += 1
        if self.down_after and self._connect_failures >= self.down_after:
            raise NetworkDown(
                f"{self._connect_failures} requests in a row failed to connect "
                f"(last: {exc})"
            ) from exc

    def get_text(self, url: str, *, limit: int | None = None) -> tuple[str, str]:
        """Fetch a body as decoded text plus its Content-Type (uncached).

        ``limit`` truncates the decoded text (body reads pass max_body_bytes).
        """
        body, content_type = self.get_bytes(url)
        if limit is not None:
            body = body[:limit]
        return body.decode("utf-8", errors="replace"), content_type

    def probe(self, url: str) -> tuple[int, str, str, str]:
        """One GET, redirects NOT followed: (status, body, content_type, location).

        Counts against the request budget. Transport failures return status 0.
        A 3xx/4xx/5xx is a valid probe result, not an error, so its code and any
        Location header come back for the caller to classify.
        """
        if self.max_requests and self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(f"request cap {self.max_requests} reached")
        self._throttle(url)
        request = Request(url, headers={"User-Agent": self.user_agent}, method="GET")
        self.request_count += 1
        opener = build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=self.timeout) as response:
                body = response.read(self.max_body_bytes + 1)[: self.max_body_bytes]
                text = body.decode("utf-8", errors="replace")
                ct = response.headers.get("Content-Type", "")
                return response.status, text, ct, ""
        except HTTPError as exc:
            headers = exc.headers
            ct = headers.get("Content-Type", "") if headers else ""
            location = headers.get("Location", "") if headers else ""
            return exc.code, "", ct, location
        except (URLError, TimeoutError, ValueError):
            return 0, "", "", ""

    def get_json(self, url: str) -> Any:
        """Fetch and parse JSON (or NDJSON), cached per URL (bounded LRU)."""
        cached = self._cache_get(url)
        if cached is not None:
            return cached
        body, content_type = self.get_bytes(url)
        data = self._parse(body.decode("utf-8", errors="replace"), content_type)
        self._cache_put(url, data)
        return data

    def clear_cache(self) -> None:
        """Drop the parsed-JSON cache (called between pipeline stages)."""
        self._json_cache.clear()

    def _cache_get(self, url: str) -> Any:
        if url not in self._json_cache:
            return None
        self._json_cache.move_to_end(url)
        return self._json_cache[url]

    def _cache_put(self, url: str, data: Any) -> None:
        if self.cache_entries <= 0:
            return
        self._json_cache[url] = data
        self._json_cache.move_to_end(url)
        while len(self._json_cache) > self.cache_entries:
            self._json_cache.popitem(last=False)

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

    def _throttle(self, url: str) -> None:
        """Wait out the interval for THIS URL's host only."""
        host = request_host(url)
        previous = self._last_at.get(host)
        if previous is not None:
            delay = self.interval - (time.monotonic() - previous)
            if delay > 0:
                time.sleep(delay)
        self._last_at[host] = time.monotonic()
