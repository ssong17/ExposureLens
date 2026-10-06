"""The unified `probe` stage: one live pass, one id space, one result."""
from __future__ import annotations

from exposure_lens.probe.prober import run_probe


class FakeHttp:
    max_requests = 1000
    max_body_bytes = 1_000_000

    def __init__(self, bodies=None):
        self._bodies = bodies or {}
        self.request_count = 0
        self.urls: list[str] = []

    def probe(self, url):
        self.request_count += 1
        self.urls.append(url)
        status, text, ct = self._bodies.get(url, (0, "", ""))
        return status, text, ct, ""

    def get_text(self, url, *, limit=None):
        self.request_count += 1
        self.urls.append(url)
        for target, (_s, text, ct) in self._bodies.items():
            if target in url:
                return text, ct
        return "", ""


def _endpoint(record_id, url, conf="high", org="x"):
    return {
        "record_id": record_id, "org_id": org, "asset_type": "endpoint",
        "apex_confidence": conf, "host": url.split("/")[2], "url": url,
        "freshness": "archived",
    }


def _host_finding(org="x"):
    return {
        "finding_id": "F1", "org_id": org, "asset_ref": "A1", "severity": "medium",
        "category": "sensitive-host", "rule": "host-vcs", "host": "git.x.com",
        "url": "", "evidence": "git.x.com",
    }


def test_finding_ids_are_unique_across_both_halves():
    """Regression: body reads and verification each numbered from 1 with the
    same prefixes, so a probe run emitted duplicate finding_ids."""
    bodies = {
        "https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript"),
        "https://git.x.com/.git/config": (200, "[core]", "text/plain"),
        "https://git.x.com/.git/HEAD": (200, "ref: refs/heads/main", "text/plain"),
    }
    http = FakeHttp(bodies)
    result = run_probe(
        http,
        [_endpoint("E1", "https://a.x.com/app.js")],
        [_host_finding()],
    )
    ids = [f.finding_id for f in result.rows]
    assert len(ids) == len(set(ids))
    # both halves actually ran
    assert any(f.source == "fetch-body" for f in result.findings)
    assert any(f.source == "verify-confirmed" for f in result.findings)


def test_liveness_is_separated_from_findings():
    http = FakeHttp({"https://a.x.com/app.js": (404, "", "")})
    result = run_probe(http, [_endpoint("E1", "https://a.x.com/app.js")], [])
    assert result.liveness and not result.findings
    assert all(f.category == "liveness" for f in result.liveness)


def test_fetched_findings_carry_current_freshness():
    """A body we just fetched is present-tense, even if collect said archived."""
    http = FakeHttp(
        {"https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript")}
    )
    result = run_probe(http, [_endpoint("E1", "https://a.x.com/app.js")], [])
    secret = next(f for f in result.findings if f.category == "leaked-secret")
    assert secret.freshness == "current"


def test_org_identity_survives_into_findings():
    """A findings row must say whose asset it is without the reader holding
    config.toml open next to it."""
    http = FakeHttp(
        {"https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript")}
    )
    asset = dict(_endpoint("E1", "https://a.x.com/app.js"), org_id="snu",
                 org_name="Seoul National University")
    result = run_probe(http, [asset], [])
    secret = next(f for f in result.findings if f.category == "leaked-secret")
    assert secret.org_id == "snu"
    assert secret.org_name == "Seoul National University"


def test_org_identity_survives_into_verification():
    http = FakeHttp({"https://git.x.com/.git/config": (200, "[core]", "text/plain")})
    finding = dict(_host_finding(), org_id="snu",
                   org_name="Seoul National University")
    result = run_probe(http, [], [finding])
    confirmed = next(f for f in result.findings if f.source == "verify-confirmed")
    assert confirmed.org_name == "Seoul National University"
    assert all(f.org_name == "Seoul National University" for f in result.liveness)


# ---- scan→probe flow: scan extracts archives, probe fills the gaps -----------

def test_restrict_body_urls_limits_fetch_to_the_misses():
    bodies = {
        "https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript"),
        "https://a.x.com/new.js": (200, 'k="AKIAZZZZZZZZZZZZZZZZ"', "text/javascript"),
    }
    http = FakeHttp(bodies)
    result = run_probe(
        http,
        [_endpoint("E1", "https://a.x.com/app.js"),
         _endpoint("E2", "https://a.x.com/new.js")],
        [],
        restrict_body_urls={"https://a.x.com/new.js"},  # only the archive miss
    )
    read = [u for u in http.urls if "new.js" in u or "app.js" in u]
    assert all("new.js" in u for u in read)  # app.js (archive had it) not re-fetched
    assert any(f.category == "leaked-secret" for f in result.findings)


def test_empty_restrict_reads_no_bodies_but_still_verifies():
    # archive covered everything (no misses): probe does zero body reads,
    # only verification of prior findings runs.
    http = FakeHttp({"https://git.x.com/.git/config": (200, "[core]", "text/plain")})
    result = run_probe(
        http, [_endpoint("E1", "https://a.x.com/app.js")], [_host_finding()],
        restrict_body_urls=set(),
    )
    assert all("app.js" not in u for u in http.urls)  # no body reads
    assert any(f.source == "verify-confirmed" for f in result.findings)  # verify ran


# ---- soft-404 / SPA catch-all must not become "current exposure" -------------

class CatchAllHttp:
    """A host that answers 200 with the same index page for ANY path (SPA)."""
    max_requests = 1000
    max_body_bytes = 1_000_000

    def __init__(self, page="<html>index</html>"):
        self.page = page
        self.request_count = 0
        self.urls = []

    def probe(self, url):
        self.request_count += 1
        self.urls.append(url)
        return 200, self.page, "text/html", ""


def test_catch_all_200_is_not_flagged_as_authz_open():
    http = CatchAllHttp()
    # an admin-ish path on an SPA that 200s everything
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/admin/")], [])
    assert not any(f.category == "access-control" for f in res.findings)
    # liveness still recorded, but no exposure
    assert any(f.category == "liveness" for f in res.liveness)


def test_catch_all_body_rules_are_skipped():
    # the catch-all page contains a secret-shaped string; must NOT be reported
    # because the body is the host's generic page, not this URL's content.
    page = 'x="AKIAABCDEFGHIJKLMNOP"'
    http = CatchAllHttp(page=page)
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/app.js")], [])
    assert not any(f.category == "leaked-secret" for f in res.findings)


def test_static_js_on_internal_path_is_not_authz_open():
    bodies = {"https://a.x.com/internal/foo.js": (200, "console.log(1)", "text/javascript")}
    http = FakeHttp(bodies)
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/internal/foo.js")], [])
    assert not any(f.category == "access-control" for f in res.findings)


def test_genuine_distinct_page_on_catch_all_host_still_inspected():
    # Host 200s a short index for bogus, but this real page is clearly different
    # (much longer) and carries a secret -> must still be found.
    class MixedHttp(CatchAllHttp):
        def probe(self, url):
            self.request_count += 1
            from urllib.parse import urlsplit
            if (urlsplit(url).path or "/") == "/":
                return 200, "idx", "text/html", ""   # short homepage baseline
            return 200, 'k="AKIAABCDEFGHIJKLMNOP"' + "x" * 500, "text/html", ""
    http = MixedHttp()
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/config")], [])
    assert any(f.category == "leaked-secret" for f in res.findings)


def test_login_page_on_admin_path_is_not_open_without_auth():
    # /admin returns 200 but it's a login FORM -> auth is enforced, not an open door.
    bodies = {"https://a.x.com/admin/": (200, '<form><input type="password"></form>', "text/html")}
    http = FakeHttp(bodies)
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/admin/")], [])
    assert not any(f.category == "access-control" for f in res.findings)


def test_admin_content_without_login_is_open_without_auth():
    # /admin returns 200 with real admin content (no login form) -> genuine breach.
    bodies = {"https://a.x.com/admin/": (200, "<h1>Admin Dashboard</h1><table>users</table>", "text/html")}
    http = FakeHttp(bodies)
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/admin/")], [])
    assert any(f.category == "access-control" for f in res.findings)
