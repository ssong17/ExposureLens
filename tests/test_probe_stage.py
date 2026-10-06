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


# ---- one pass over the full set (no restrict): every endpoint is read live ---

def test_probe_reads_every_collected_endpoint_live():
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
    )
    read = {u for u in http.urls if "app.js" in u or "new.js" in u}
    assert any("app.js" in u for u in read) and any("new.js" in u for u in read)
    assert sum(f.category == "leaked-secret" for f in result.findings) == 2


def test_max_targets_caps_and_reports():
    assets = [_endpoint(f"E{i}", f"https://a.x.com/{i}.js") for i in range(5)]
    http = FakeHttp({})
    result = run_probe(http, assets, [], max_targets=2)
    assert any("capped targets" in p for p in result.problems)


def test_host_finding_confirmed_via_implied_path():
    # a host-level finding (no URL) is probed at the exact path it implies
    http = FakeHttp({"https://git.x.com/.git/config": (200, "[core]", "text/plain")})
    result = run_probe(http, [], [_host_finding()])
    assert any(f.source == "verify-confirmed" and f.url.endswith("/.git/config")
               for f in result.findings)


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


def test_login_page_on_admin_path_is_auth_panel_not_open():
    # /admin returns 200 but it's a login FORM -> not "open without auth", but a
    # reachable login = credential-stuffing surface, recorded as auth-panel.
    bodies = {"https://a.x.com/admin/": (200, '<form><input type="password"></form>', "text/html")}
    http = FakeHttp(bodies)
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/admin/")], [])
    assert not any(f.category == "access-control" for f in res.findings)
    assert any(f.category == "auth-panel" for f in res.findings)


def test_admin_content_without_login_is_open_without_auth():
    # /admin returns 200 with real admin content (no login form) -> genuine breach.
    bodies = {"https://a.x.com/admin/": (200, "<h1>Admin Dashboard</h1><table>users</table>", "text/html")}
    http = FakeHttp(bodies)
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/admin/")], [])
    assert any(f.category == "access-control" for f in res.findings)


def test_no_authz_flag_when_redirected():
    http = FakeHttp({"https://a.x.com/admin": (302, "", "text/html")})
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/admin")], [])
    assert not any(f.category == "access-control" for f in res.findings)
    assert any(f.category == "liveness" for f in res.liveness)


def test_follows_inline_sourcemap():
    import base64
    import json
    original = 'if(user.isAdmin){fetch("/api/v1/admin/users");}'
    sm = base64.b64encode(json.dumps(
        {"version": 3, "sources": ["src/Admin.js"], "sourcesContent": [original]}
    ).encode()).decode()
    minified = "function A(u){}\n//# sourceMappingURL=data:application/json;base64," + sm
    http = FakeHttp({"https://a.x.com/app.js": (200, minified, "application/javascript")})
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/app.js")], [])
    sm_cats = {f.category for f in res.findings if f.source and "sourcemap" in f.source}
    assert {"client-authz", "api-endpoint"} <= sm_cats


def test_script_hop_pulls_same_origin_scripts_from_homepage():
    # homepage links a script collect never found; probe should pull it (capped)
    # and read it, but NOT cross-origin ones.
    bodies = {
        "https://a.x.com/": (200, '<script src="/assets/secret.js"></script>'
                             '<script src="https://cdn.other.com/x.js"></script>', "text/html"),
        "https://a.x.com/assets/secret.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript"),
    }
    http = FakeHttp(bodies)
    # seed with one endpoint on the host so the homepage gets fetched
    res = run_probe(http, [_endpoint("E1", "https://a.x.com/page")], [], script_hop=3)
    assert any("/assets/secret.js" in u for u in http.urls)       # same-origin pulled
    assert not any("cdn.other.com" in u for u in http.urls)       # cross-origin skipped
    assert any(f.category == "leaked-secret" for f in res.findings)


def test_default_reads_all_same_origin_scripts():
    # default script_hop=0 -> every same-origin script the homepage links is read
    links = "".join(f'<script src="/s{i}.js"></script>' for i in range(6))
    bodies = {"https://a.x.com/": (200, links, "text/html")}
    for i in range(6):
        bodies[f"https://a.x.com/s{i}.js"] = (200, f"var x={i}", "text/javascript")
    http = FakeHttp(bodies)
    run_probe(http, [_endpoint("E1", "https://a.x.com/page")], [])  # no cap
    fetched = {u for u in http.urls if u.endswith(".js")}
    assert len(fetched) == 6  # all six, not a capped subset
