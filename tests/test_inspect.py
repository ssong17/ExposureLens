"""Body inspection: target/confidence gating, secrets, authz, sourcemaps."""
from __future__ import annotations

from exposure_lens.probe.inspect import FETCH, WAYBACK, _select_targets, inspect_assets


def _endpoint(record_id: str, url: str, conf: str = "high") -> dict:
    return {
        "record_id": record_id,
        "org_id": "x",
        "asset_type": "endpoint",
        "apex_confidence": conf,
        "host": (url.split("/")[2] if "//" in url else "a.x.com"),
        "url": url,
    }


class FakeHttp:
    """Stand-in for core.net.Http: serves canned bodies/statuses per URL."""

    max_body_bytes = 1_000_000

    def __init__(self, bodies: dict[str, tuple[int, str, str]]):
        self._bodies = bodies  # url -> (status, text, content_type)
        self.request_count = 0
        self.max_requests = 1000

    def get_text(self, url: str, *, limit: int | None = None) -> tuple[str, str]:
        self.request_count += 1
        # inspect asks for the wayback snapshot URL; match on the wrapped target.
        for target, (_s, text, ct) in self._bodies.items():
            if target in url:
                return text, ct
        return "", ""

    def probe(self, url: str) -> tuple[int, str, str, str]:
        self.request_count += 1
        status, text, ct = self._bodies.get(url, (0, "", ""))
        return status, text, ct, ""


# ---- target selection --------------------------------------------------------

def test_select_targets_endpoints_only_and_confidence_gate():
    assets = [
        _endpoint("E1", "https://a.x.com/app.js", conf="high"),
        _endpoint("E2", "https://b.x.com/c.js", conf="medium"),
        {"record_id": "S1", "asset_type": "subdomain", "host": "a.x.com", "url": ""},
    ]
    # fetch rank = high only
    high_only = _select_targets(assets, None, 0)
    assert [t["record_id"] for t in high_only] == ["E1"]
    # wayback rank = high+medium
    both = _select_targets(assets, None, 1)
    assert {t["record_id"] for t in both} == {"E1", "E2"}


def test_select_targets_only_findings_filter():
    assets = [
        _endpoint("E1", "https://a.x.com/a.js"),
        _endpoint("E2", "https://a.x.com/b.js"),
    ]
    picked = _select_targets(assets, {"https://a.x.com/b.js"}, 0)
    assert [t["record_id"] for t in picked] == ["E2"]


# ---- end-to-end via fake http ------------------------------------------------

def test_inspect_wayback_finds_secret_in_snapshot():
    body = 'const k = "AKIAABCDEFGHIJKLMNOP";'
    http = FakeHttp({"https://a.x.com/app.js": (200, body, "application/javascript")})
    findings, problems = inspect_assets(
        http,
        [_endpoint("E1", "https://a.x.com/app.js")],
        source=WAYBACK,
        min_severity="low",
    )
    assert not problems
    assert any(
        f.category == "leaked-secret" and f.source == "wayback-body" for f in findings
    )


def test_inspect_fetch_flags_unauthenticated_admin():
    http = FakeHttp({"https://a.x.com/admin/users": (200, "<html>admin</html>", "text/html")})
    findings, _ = inspect_assets(
        http,
        [_endpoint("E1", "https://a.x.com/admin/users")],
        source=FETCH,
        min_severity="low",
    )
    authz = [f for f in findings if f.category == "access-control"]
    assert authz and authz[0].severity == "high" and authz[0].status == "200"


def test_inspect_fetch_no_authz_flag_when_redirected():
    http = FakeHttp({"https://a.x.com/admin": (302, "", "text/html")})
    findings, _ = inspect_assets(
        http, [_endpoint("E1", "https://a.x.com/admin")], source=FETCH, min_severity="low",
    )
    assert not any(f.category == "access-control" for f in findings)


def test_inspect_max_targets_caps_and_reports():
    assets = [_endpoint(f"E{i}", f"https://a.x.com/{i}.js") for i in range(5)]
    http = FakeHttp({})
    _, problems = inspect_assets(http, assets, source=WAYBACK, max_targets=2)
    assert any("capped targets" in p for p in problems)


def test_inspect_follows_inline_sourcemap():
    import base64
    import json

    original = 'if(user.isAdmin){fetch("/api/v1/admin/users");}'
    sm = base64.b64encode(json.dumps(
        {"version": 3, "sources": ["src/Admin.js"], "sourcesContent": [original]}
    ).encode()).decode()
    minified = "function A(u){}\n//# sourceMappingURL=data:application/json;base64," + sm
    http = FakeHttp({"https://h/app.js": (200, minified, "application/javascript")})
    findings, _ = inspect_assets(
        http,
        [_endpoint("E1", "https://h/app.js")],
        source=FETCH,
        min_severity="low",
    )
    sm_cats = {f.category for f in findings if f.source and "sourcemap" in f.source}
    # The minified bundle hid these; the source map restores them.
    assert {"client-authz", "api-endpoint"} <= sm_cats
