"""Body-reading engine (scan.bodyscan): target/confidence gating, secrets,
authz, sourcemaps — plus the scan-stage archive pass (scan_archive_bodies) and its
resume."""
from __future__ import annotations

from exposure_lens.scan.bodyscan import (
    FETCH,
    WAYBACK,
    _select_targets,
    read_bodies,
    scan_archive_bodies,
)


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
        self.urls: list[str] = []

    def get_text(self, url: str, *, limit: int | None = None) -> tuple[str, str]:
        self.request_count += 1
        self.urls.append(url)
        # the wayback snapshot URL wraps the target; match on the wrapped target.
        for target, (_s, text, ct) in self._bodies.items():
            if target in url:
                return text, ct
        return "", ""

    def probe(self, url: str) -> tuple[int, str, str, str]:
        self.request_count += 1
        self.urls.append(url)
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


# ---- read_bodies end-to-end via fake http ------------------------------------

def test_read_bodies_wayback_finds_secret_in_snapshot():
    body = 'const k = "AKIAABCDEFGHIJKLMNOP";'
    http = FakeHttp({"https://a.x.com/app.js": (200, body, "application/javascript")})
    findings, problems = read_bodies(
        http,
        [_endpoint("E1", "https://a.x.com/app.js")],
        source=WAYBACK,
        min_severity="low",
    )
    assert not problems
    assert any(
        f.category == "leaked-secret" and f.source == "wayback-body" for f in findings
    )


def test_read_bodies_fetch_flags_unauthenticated_admin():
    http = FakeHttp({"https://a.x.com/admin/users": (200, "<html>admin</html>", "text/html")})
    findings, _ = read_bodies(
        http,
        [_endpoint("E1", "https://a.x.com/admin/users")],
        source=FETCH,
        min_severity="low",
    )
    authz = [f for f in findings if f.category == "access-control"]
    assert authz and authz[0].severity == "high" and authz[0].status == "200"


def test_read_bodies_fetch_no_authz_flag_when_redirected():
    http = FakeHttp({"https://a.x.com/admin": (302, "", "text/html")})
    findings, _ = read_bodies(
        http, [_endpoint("E1", "https://a.x.com/admin")], source=FETCH, min_severity="low",
    )
    assert not any(f.category == "access-control" for f in findings)


def test_read_bodies_max_targets_caps_and_reports():
    assets = [_endpoint(f"E{i}", f"https://a.x.com/{i}.js") for i in range(5)]
    http = FakeHttp({})
    _, problems = read_bodies(http, assets, source=WAYBACK, max_targets=2)
    assert any("capped targets" in p for p in problems)


def test_read_bodies_follows_inline_sourcemap():
    import base64
    import json

    original = 'if(user.isAdmin){fetch("/api/v1/admin/users");}'
    sm = base64.b64encode(json.dumps(
        {"version": 3, "sources": ["src/Admin.js"], "sourcesContent": [original]}
    ).encode()).decode()
    minified = "function A(u){}\n//# sourceMappingURL=data:application/json;base64," + sm
    http = FakeHttp({"https://h/app.js": (200, minified, "application/javascript")})
    findings, _ = read_bodies(
        http,
        [_endpoint("E1", "https://h/app.js")],
        source=FETCH,
        min_severity="low",
    )
    sm_cats = {f.category for f in findings if f.source and "sourcemap" in f.source}
    # The minified bundle hid these; the source map restores them.
    assert {"client-authz", "api-endpoint"} <= sm_cats


# ---- scan_archive_bodies (scan-stage archive entry point) -------------------------------

def test_archive_reads_the_archive_not_the_target():
    http = FakeHttp(
        {"https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript")}
    )
    findings, missed, problems = scan_archive_bodies(
        http, [_endpoint("E1", "https://a.x.com/app.js")], min_severity="low",
    )
    assert any(f.category == "leaked-secret" for f in findings)
    assert all("web.archive.org" in u for u in http.urls)  # target never touched
    assert missed == []


def test_archive_findings_stay_archived():
    http = FakeHttp(
        {"https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript")}
    )
    findings, _missed, _ = scan_archive_bodies(
        http, [_endpoint("E1", "https://a.x.com/app.js")], min_severity="low",
    )
    secret = next(f for f in findings if f.category == "leaked-secret")
    assert secret.freshness == "archived"


def test_archive_records_missed_endpoints():
    # app.js has an archive snapshot; new.js has none (returns 0/empty).
    http = FakeHttp(
        {"https://a.x.com/app.js": (200, "clean body", "text/javascript")}
    )
    _findings, missed, _ = scan_archive_bodies(
        http,
        [_endpoint("E1", "https://a.x.com/app.js"),
         _endpoint("E2", "https://a.x.com/new.js")],
        min_severity="low",
    )
    assert missed == ["https://a.x.com/new.js"]


def test_archive_resume_replays_done_urls_without_refetching():
    """The resumable archive pass: a URL already recorded is replayed from the
    stored findings, and only the unseen URL is fetched again."""
    recorded: dict[str, list[dict]] = {}
    missed_flags: dict[str, bool] = {}

    def on_result(url, findings, missed):
        recorded[url] = findings
        missed_flags[url] = missed

    http1 = FakeHttp({
        "https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript"),
        "https://a.x.com/b.js": (200, 'k="AKIAZZZZZZZZZZZZZZZZ"', "text/javascript"),
    })
    assets = [
        _endpoint("E1", "https://a.x.com/app.js"),
        _endpoint("E2", "https://a.x.com/b.js"),
    ]
    first, _m, _ = scan_archive_bodies(
        http1, assets, min_severity="low", on_result=on_result,
    )
    assert len(recorded) == 2

    # Resume: app.js is already done, only b.js (dropped from `done`) is fetched.
    done = {"https://a.x.com/app.js": recorded["https://a.x.com/app.js"]}
    http2 = FakeHttp({
        "https://a.x.com/b.js": (200, 'k="AKIAZZZZZZZZZZZZZZZZ"', "text/javascript"),
    })
    second, _m2, _ = scan_archive_bodies(
        http2, assets, min_severity="low", done=done,
    )
    assert not any("app.js" in u for u in http2.urls)  # replayed, not re-fetched
    assert any("b.js" in u for u in http2.urls)
    # Both URLs still represented in the result.
    assert {f.category for f in second} >= {"leaked-secret"}
    ids = [f.finding_id for f in second]
    assert len(ids) == len(set(ids))  # fresh ids, no collision on replay


def test_archive_resume_missed_flag_is_explicit_not_inferred():
    """A replayed URL that HAD a snapshot but no findings must not be re-reported
    as a miss; only the real misses (done_missed) are."""
    http = FakeHttp({})  # nothing fetched: everything comes from `done`
    assets = [
        _endpoint("E1", "https://a.x.com/clean.js"),  # snapshot, zero findings
        _endpoint("E2", "https://a.x.com/gone.js"),   # genuinely missed
    ]
    done = {"https://a.x.com/clean.js": [], "https://a.x.com/gone.js": []}
    done_missed = {"https://a.x.com/gone.js"}
    _findings, missed, _ = scan_archive_bodies(
        http, assets, min_severity="low", done=done, done_missed=done_missed,
    )
    assert missed == ["https://a.x.com/gone.js"]  # clean.js NOT re-flagged missed
    assert http.urls == []  # fully replayed, nothing fetched
