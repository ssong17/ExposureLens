"""The unified active stage: one pass, one id space, one set of results."""
from __future__ import annotations

from exposure_lens.probe.inspect import FETCH, WAYBACK, run_inspection


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
    """Regression: inspection and verification each numbered from 1 with the
    same prefixes, so a probe run emitted duplicate finding_ids."""
    bodies = {
        "https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript"),
        "https://git.x.com/.git/config": (200, "[core]", "text/plain"),
        "https://git.x.com/.git/HEAD": (200, "ref: refs/heads/main", "text/plain"),
    }
    http = FakeHttp(bodies)
    result = run_inspection(
        http,
        [_endpoint("E1", "https://a.x.com/app.js")],
        [_host_finding()],
        source=FETCH,
    )
    ids = [f.finding_id for f in result.rows]
    assert len(ids) == len(set(ids))
    # both halves actually ran
    assert any(f.source == "fetch-body" for f in result.findings)
    assert any(f.source == "verify-confirmed" for f in result.findings)


def test_wayback_source_reads_the_archive_not_the_target():
    http = FakeHttp(
        {"https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript")}
    )
    result = run_inspection(
        http, [_endpoint("E1", "https://a.x.com/app.js")], [],
        source=WAYBACK,
    )
    assert any(f.category == "leaked-secret" for f in result.findings)
    assert all("web.archive.org" in u for u in http.urls)  # target never touched


def test_liveness_is_separated_from_findings():
    http = FakeHttp({"https://a.x.com/app.js": (404, "", "")})
    result = run_inspection(
        http, [_endpoint("E1", "https://a.x.com/app.js")], [],
        source=FETCH,
    )
    assert result.liveness and not result.findings
    assert all(f.category == "liveness" for f in result.liveness)


def test_fetched_findings_carry_current_freshness():
    """A body we just fetched is present-tense, even if collect said archived."""
    http = FakeHttp(
        {"https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript")}
    )
    result = run_inspection(
        http, [_endpoint("E1", "https://a.x.com/app.js")], [],
        source=FETCH,
    )
    secret = next(f for f in result.findings if f.category == "leaked-secret")
    assert secret.freshness == "current"


def test_archived_findings_stay_archived():
    http = FakeHttp(
        {"https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript")}
    )
    result = run_inspection(
        http, [_endpoint("E1", "https://a.x.com/app.js")], [],
        source=WAYBACK,
    )
    secret = next(f for f in result.findings if f.category == "leaked-secret")
    assert secret.freshness == "archived"


def test_wayback_source_skips_verification_entirely():
    """`--source wayback` is documented as target-free, but verification can
    only work by probing live. Running it on an archived pass contradicted the
    label, so verification is now confined to the fetch pass."""
    http = FakeHttp()
    result = run_inspection(
        http, [], [_host_finding()], source=WAYBACK,
    )
    assert http.urls == []          # git.x.com was never contacted
    assert result.rows == []


def test_org_identity_survives_into_findings():
    """A findings row must say whose asset it is without the reader holding
    config.toml open next to it."""
    http = FakeHttp(
        {"https://a.x.com/app.js": (200, 'k="AKIAABCDEFGHIJKLMNOP"', "text/javascript")}
    )
    asset = dict(_endpoint("E1", "https://a.x.com/app.js"), org_id="snu",
                 org_name="Seoul National University")
    result = run_inspection(http, [asset], [], source=FETCH)
    secret = next(f for f in result.findings if f.category == "leaked-secret")
    assert secret.org_id == "snu"
    assert secret.org_name == "Seoul National University"


def test_org_identity_survives_into_verification():
    http = FakeHttp({"https://git.x.com/.git/config": (200, "[core]", "text/plain")})
    finding = dict(_host_finding(), org_id="snu",
                   org_name="Seoul National University")
    result = run_inspection(http, [], [finding], source=FETCH)
    confirmed = next(f for f in result.findings if f.source == "verify-confirmed")
    assert confirmed.org_name == "Seoul National University"
    assert all(f.org_name == "Seoul National University" for f in result.liveness)
