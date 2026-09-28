from __future__ import annotations

import urllib.error

import pytest

from exposure_lens.core import net


def _http(**kw):
    base = dict(user_agent="t", interval=0, timeout=1, max_retries=3,
                max_bytes=1000, max_requests=100, retry_delays=(0,))
    base.update(kw)
    return net.Http(**base)


class _Resp:
    def __init__(self, body=b"ok"):
        self._body = body
        self.headers = {"Content-Type": "application/json"}

    def read(self, n):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(code):
    return urllib.error.HTTPError("u", code, "err", None, None)


def test_retries_transient_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout):
        calls["n"] += 1
        if calls["n"] < 3:
            raise _http_error(502)  # transient twice
        return _Resp()

    monkeypatch.setattr(net, "urlopen", fake_urlopen)
    monkeypatch.setattr(net.time, "sleep", lambda s: None)
    body, _ = _http().get_bytes("https://crt.sh/x")
    assert body == b"ok"
    assert calls["n"] == 3  # retried, did not skip


def test_404_is_not_retried(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout):
        calls["n"] += 1
        raise _http_error(404)  # "no results": not transient

    monkeypatch.setattr(net, "urlopen", fake_urlopen)
    monkeypatch.setattr(net.time, "sleep", lambda s: None)
    with pytest.raises(urllib.error.HTTPError):
        _http().get_bytes("https://crt.sh/x")
    assert calls["n"] == 1  # single attempt, no retry


def test_exhausts_retries_then_raises(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout):
        calls["n"] += 1
        raise _http_error(503)

    monkeypatch.setattr(net, "urlopen", fake_urlopen)
    monkeypatch.setattr(net.time, "sleep", lambda s: None)
    notices = []
    h = _http(max_retries=2, on_retry=notices.append)
    with pytest.raises(urllib.error.HTTPError):
        h.get_bytes("https://crt.sh/x")
    assert calls["n"] == 3  # initial + 2 retries
    assert len(notices) == 2  # a notice per retry


# ---- per-host throttling -----------------------------------------------------

def test_throttle_is_per_host(monkeypatch):
    """crt.sh's interval must not make the Shodan pass wait as well."""
    slept: list[float] = []
    clock = {"t": 0.0}
    monkeypatch.setattr(net.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(net.time, "monotonic", lambda: clock["t"])

    h = _http(interval=2.0)
    h._throttle("https://crt.sh/a")
    h._throttle("https://internetdb.shodan.io/1.1.1.1")  # different host
    assert slept == []  # no wait: the two services are independent

    h._throttle("https://crt.sh/b")  # same host, no time has passed
    assert slept == [2.0]


def test_cache_is_bounded(monkeypatch):
    h = _http(cache_entries=2)
    for i in range(5):
        h._cache_put(f"u{i}", i)
    assert len(h._json_cache) == 2
    assert h._cache_get("u0") is None   # evicted
    assert h._cache_get("u4") == 4


def test_cache_get_refreshes_lru():
    h = _http(cache_entries=2)
    h._cache_put("a", 1)
    h._cache_put("b", 2)
    h._cache_get("a")       # 'a' is now the most recent
    h._cache_put("c", 3)    # evicts 'b'
    assert h._cache_get("b") is None
    assert h._cache_get("a") == 1


def test_body_cap_is_separate_from_response_cap():
    h = _http(max_bytes=1000, max_body_bytes=100)
    assert h.max_body_bytes == 100
    # A body cap can never exceed the response cap.
    assert _http(max_bytes=100, max_body_bytes=9999).max_body_bytes == 100


def test_retry_waits_climb_5_15_30(monkeypatch):
    waits = []

    def fake_urlopen(req, timeout):
        raise _http_error(503)

    monkeypatch.setattr(net, "urlopen", fake_urlopen)
    monkeypatch.setattr(net.time, "sleep", waits.append)
    h = _http(retry_delays=net.DEFAULT_RETRY_DELAYS)
    with pytest.raises(urllib.error.HTTPError):
        h.get_bytes("https://crt.sh/x")
    assert waits == [5.0, 15.0, 30.0]


def test_retry_past_the_ladder_reuses_its_last_rung():
    h = _http(retry_delays=(5, 15))
    assert [h.retry_delay(a) for a in range(4)] == [5, 15, 15, 15]


def _refused(req, timeout):
    raise urllib.error.URLError(ConnectionRefusedError("refused"))


def test_network_down_after_consecutive_connect_failures(monkeypatch):
    monkeypatch.setattr(net, "urlopen", _refused)
    monkeypatch.setattr(net.time, "sleep", lambda s: None)
    h = _http(max_retries=0, down_after=3)
    for host in ("crt.sh", "web.archive.org"):  # different hosts still add up
        with pytest.raises(urllib.error.URLError):
            h.get_bytes(f"https://{host}/x")
    with pytest.raises(net.NetworkDown):
        h.get_bytes("https://urlscan.io/x")
    assert h.connect_failure_total == 3


def test_server_answer_or_slow_query_is_not_network_down(monkeypatch):
    """A 502 proves the link works; a read timeout is crt.sh being slow."""
    errors = iter([
        urllib.error.URLError(ConnectionRefusedError("refused")),
        _http_error(502),
        urllib.error.URLError(ConnectionRefusedError("refused")),
        TimeoutError("read timed out"),
        urllib.error.URLError(ConnectionRefusedError("refused")),
    ])

    def fake_urlopen(req, timeout):
        raise next(errors)

    monkeypatch.setattr(net, "urlopen", fake_urlopen)
    h = _http(max_retries=0, down_after=2)
    for _ in range(5):
        with pytest.raises((urllib.error.URLError, TimeoutError)):
            h.get_bytes("https://crt.sh/x")
    assert h.connect_failure_total == 3  # counted, but never 2 in a row


def test_success_resets_the_connect_failure_streak(monkeypatch):
    results = iter([_refused, _refused, None, _refused, _refused])

    def fake_urlopen(req, timeout):
        fn = next(results)
        if fn is None:
            return _Resp()
        return fn(req, timeout)

    monkeypatch.setattr(net, "urlopen", fake_urlopen)
    h = _http(max_retries=0, down_after=3)
    for _ in range(5):
        try:
            h.get_bytes("https://crt.sh/x")
        except urllib.error.URLError:
            pass  # never NetworkDown: the success in the middle reset it
