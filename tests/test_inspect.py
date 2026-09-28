from __future__ import annotations

from exposure_lens.core.models import FindingIds
from exposure_lens.probe.inspect import FETCH, WAYBACK, _select_targets, inspect_assets
from exposure_lens.scan.scanner import _mask_match, scan_body


def _ids():
    return FindingIds("T", date="20260101")


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

    def __init__(self, bodies: dict[str, tuple[int, str, str]]):
        self._bodies = bodies  # url -> (status, text, content_type)
        self.request_count = 0
        self.max_requests = 1000

    max_body_bytes = 1_000_000

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


# ---- content masking ---------------------------------------------------------

def test_mask_match_keeps_key_hides_value():
    masked = _mask_match('password: "hunter2secret"')
    assert "hunter2secret" not in masked
    assert masked.startswith("password:")


def test_scan_body_detects_and_masks_categories():
    body = (
        'apiKey: "AKIAABCDEFGHIJKLMNOP"\n'
        'DATABASE_URL = "postgres://admin:s3cr3tpw@db.internal:5432/prod"\n'
        "resident 900101-1234567\n"
    )
    fs = scan_body(
        body,
        asset={"record_id": "R1", "org_id": "x", "host": "a.x.com"},
        url="https://a.x.com/app.js",
        status="200",
        source="fetch-body",
        min_severity="low",
        next_id=_ids(),
    )
    cats = {f.category for f in fs}
    assert {"leaked-secret", "db-exposure", "pii-exposure"} <= cats
    assert all("s3cr3tpw" not in f.evidence for f in fs)
    assert all("1234567" not in f.evidence for f in fs)


def test_scan_body_respects_min_severity():
    body = 'resident 900101-1234567'  # high-severity pii rule
    assert scan_body(
        body, asset={"record_id": "R", "host": "h"}, url="u", status="",
        source="wayback-body", min_severity="high", next_id=_ids(),
    )
    assert not scan_body(
        body, asset={"record_id": "R", "host": "h"}, url="u", status="",
        source="wayback-body", min_severity="critical", next_id=_ids(),
    )


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
    assert any(f.category == "leaked-secret" and f.source == "wayback-body" for f in findings)


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
    import base64 as _b64
    import json as _json
    from exposure_lens.probe.inspect import inspect_assets

    original = 'if(user.isAdmin){fetch("/api/v1/admin/users");}'
    sm = _b64.b64encode(_json.dumps(
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



def test_services_flags_risky_ports_and_cves():
    from exposure_lens.scan.services import check_exposure

    class H:
        request_count = 0
        max_requests = 100
        def get_json(self, url):
            self.request_count += 1
            ip = url.rsplit("/", 1)[-1]
            data = {"1.1.1.1": {"ports": [443, 3306], "vulns": ["CVE-2024-9"]}}
            if ip not in data:
                raise Exception("404")
            return data[ip]

    from exposure_lens.scan.services import build_ip_index

    index = build_ip_index([
        {"resolved_ip": "1.1.1.1", "host": "db.x.com", "org_id": "x", "asn": "AS1"},
        {"resolved_ip": "2.2.2.2", "host": "ok.x.com", "org_id": "x", "asn": "AS1"},
    ])
    fs, _ = check_exposure(H(), index, min_severity="low")
    cats = {(f.category, f.rule) for f in fs}
    assert ("exposed-service", "port-3306") in cats  # mysql exposed (a fact)
    # CVEs are version-inferred, not confirmed — we do not report them.
    assert not any(f.category == "known-cve" for f in fs)
    assert all("2.2.2.2" not in f.evidence for f in fs)  # clean IP: nothing


def test_urlscan_observations_carry_recency():
    from exposure_lens.sources import urlscan

    class H:
        def get_json(self, url):
            return {"results": [
                {"page": {"url": "https://a.x.com/p", "status": 200},
                 "task": {"time": "2026-09-01T12:00:00.000Z", "url": "https://a.x.com/t"}},
            ]}

    obs = urlscan.fetch_observations(H(), "x.com")
    assert any(o["seen"] == "2026-09-01" for o in obs)
    assert any(o["status"] == "200" for o in obs)


def test_urlscan_paginates_beyond_one_page():
    from exposure_lens.sources import urlscan

    class H:
        def __init__(self):
            self.calls = []

        def get_json(self, url):
            self.calls.append(url)
            page = len(self.calls)
            if page > 2:
                return {"results": [], "has_more": False}
            return {
                "results": [
                    {"page": {"url": f"https://a.x.com/p{page}-{i}", "status": 200},
                     "task": {"time": "2026-09-01T00:00:00.000Z",
                              "url": f"https://a.x.com/p{page}-{i}"},
                     "sort": [page * 100 + i, "id"]}
                    for i in range(urlscan.PAGE_SIZE)
                ],
                "has_more": page < 2,
            }

    http = H()
    obs = urlscan.fetch_observations(http, "x.com", limit=150)
    assert len(obs) == 150
    assert len(http.calls) == 2
    assert "search_after=" in http.calls[1]


def test_urlscan_dedupes_identical_page_and_task_urls():
    from exposure_lens.sources import urlscan

    class H:
        def get_json(self, url):
            return {"results": [{
                "page": {"url": "https://a.x.com/p", "status": 200},
                "task": {"time": "2026-09-01T00:00:00.000Z",
                         "url": "https://a.x.com/p"},
            }], "has_more": False}

    obs = urlscan.fetch_observations(H(), "x.com")
    assert len(obs) == 1  # one URL, not the same one twice
