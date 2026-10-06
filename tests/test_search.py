"""Search-engine discovery source (opt-in --search); keyless -> no-op."""
from __future__ import annotations

import json

from exposure_lens.sources import search


class _Http:
    user_agent = "t"
    timeout = 5
    max_bytes = 1_000_000

    def __init__(self, payload):
        self._payload = payload
        self.urls = []

    def get_json(self, url):
        self.urls.append(url)
        return self._payload


def test_no_keys_returns_nothing(monkeypatch):
    for k in ("GOOGLE_API_KEY", "GOOGLE_CSE_ID", "BRAVE_SEARCH_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert search.fetch_observations(_Http({}), "x.com") == []


def test_google_cse_results_are_shaped(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "k")
    monkeypatch.setenv("GOOGLE_CSE_ID", "cse")
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    http = _Http({"items": [{"link": "https://x.com/admin"},
                            {"link": "https://x.com/login"}]})
    # kr_only=False to exercise shaping on a non-.kr apex without the KR filter.
    obs = search.fetch_observations(http, "x.com", limit=10, provider="google",
                                    kr_only=False)
    urls = {o["url"] for o in obs}
    assert urls == {"https://x.com/admin", "https://x.com/login"}
    assert all(o["seen"] == "" and o["status"] == "" for o in obs)
    assert any("customsearch" in u for u in http.urls)


def test_kr_filter_keeps_kr_tld_and_hangul_drops_the_rest(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "k")
    monkeypatch.setenv("GOOGLE_CSE_ID", "cse")
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    http = _Http({"items": [
        {"link": "https://a.co.kr/admin", "title": "관리자", "snippet": ""},  # .kr
        {"link": "https://x.com/login", "title": "로그인 페이지"},            # Hangul
        {"link": "https://x.com/en/admin", "title": "Admin", "snippet": "sign in"},  # neither
    ]})
    urls = {o["url"] for o in search.fetch_observations(http, "x.com", provider="google")}
    assert urls == {"https://a.co.kr/admin", "https://x.com/login"}  # non-KR dropped


def test_kr_filter_is_default_on(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "k")
    monkeypatch.setenv("GOOGLE_CSE_ID", "cse")
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    http = _Http({"items": [{"link": "https://x.com/admin", "title": "Admin"}]})
    assert search.fetch_observations(http, "x.com", provider="google") == []


def test_bare_keyword_becomes_site_query():
    assert search._as_query("관리자", "x.com") == 'site:x.com "관리자"'
    assert search._as_query("백업", "x.com") == 'site:x.com "백업"'


def test_template_with_apex_used_verbatim():
    assert search._as_query("site:{apex} inurl:admin", "x.com") == "site:x.com inurl:admin"


def test_custom_queries_override_defaults(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "k")
    monkeypatch.setenv("GOOGLE_CSE_ID", "cse")
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    http = _Http({"items": [{"link": "https://x.com/hit"}]})
    search.fetch_observations(http, "x.com", provider="google", queries=["백업"])
    # the custom keyword was wrapped and sent, defaults were not used
    assert any('q=' in u and "%EB%B0%B1%EC%97%85" in u or '백업' in u for u in http.urls) \
        or any("site" in u for u in http.urls)


def test_default_query_set_is_scoped_and_nonempty():
    from exposure_lens.sources.search import DEFAULT_QUERIES
    assert len(DEFAULT_QUERIES) >= 6
    assert all("{apex}" in q for q in DEFAULT_QUERIES)  # all site-scoped


def test_no_keys_makes_no_requests(monkeypatch):
    for k in ("GOOGLE_API_KEY", "GOOGLE_CSE_ID", "BRAVE_SEARCH_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    http = _Http({})
    out = search.fetch_observations(http, "x.com")  # default-on path, no keys
    assert out == [] and http.urls == []  # zero requests -> safe to default on
