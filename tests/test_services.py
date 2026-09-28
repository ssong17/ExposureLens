"""scan.services: Shodan current-service findings and IP attribution."""
from __future__ import annotations

from urllib.error import HTTPError

from exposure_lens.scan.services import (
    SHARED_HOST_LIMIT,
    build_ip_index,
    check_exposure,
)


class FakeHttp:
    request_count = 0
    max_requests = 100

    def __init__(self, records):
        self._records = records

    def get_json(self, url):
        FakeHttp.request_count = self.request_count + 1
        ip = url.rsplit("/", 1)[-1]
        if ip not in self._records:
            raise HTTPError(url, 404, "not found", None, None)  # no data
        return self._records[ip]


def _asset(ip, host, org="x", asn="AS1"):
    return {"resolved_ip": ip, "host": host, "org_id": org, "asn": asn}


def test_dedicated_ip_keeps_full_severity():
    index = build_ip_index([_asset("1.1.1.1", "db.x.com")])
    http = FakeHttp({"1.1.1.1": {"ports": [3306]}})
    findings, _ = check_exposure(http, index, min_severity="low")
    assert findings[0].severity == "critical"
    assert findings[0].category == "exposed-service"
    assert "AS1" in findings[0].evidence


def test_many_hosts_on_one_ip_is_downgraded_and_labelled():
    assets = [
        _asset("1.1.1.1", f"h{i}.x.com") for i in range(SHARED_HOST_LIMIT + 1)
    ]
    index = build_ip_index(assets)
    http = FakeHttp({"1.1.1.1": {"ports": [3306]}})
    findings, problems = check_exposure(http, index, min_severity="low")
    assert findings[0].severity == "high"  # critical -> one notch down
    assert findings[0].category == "shared-service"
    assert "shared-ip" in findings[0].evidence
    assert any("shared/CDN" in p for p in problems)


def test_cross_org_ip_is_downgraded():
    index = build_ip_index(
        [_asset("1.1.1.1", "a.x.com", org="x"), _asset("1.1.1.1", "b.y.com", org="y")]
    )
    http = FakeHttp({"1.1.1.1": {"ports": [6379]}})
    findings, _ = check_exposure(http, index, min_severity="low")
    assert findings[0].severity == "high"
    assert "shared across orgs" in findings[0].evidence


def test_primary_host_is_deterministic_not_arbitrary():
    # Insertion order used to decide which host got the blame.
    index = build_ip_index(
        [_asset("1.1.1.1", "zzz.long.host.x.com"), _asset("1.1.1.1", "a.x.com")]
    )
    assert index["1.1.1.1"].primary_host == "a.x.com"


def test_service_findings_are_marked_current():
    index = build_ip_index([_asset("1.1.1.1", "db.x.com")])
    http = FakeHttp({"1.1.1.1": {"ports": [3306]}})
    findings, _ = check_exposure(http, index, min_severity="low")
    assert findings[0].freshness == "current"


def test_service_findings_carry_org_identity():
    index = build_ip_index([
        {"resolved_ip": "1.1.1.1", "host": "db.x.com", "org_id": "snu",
         "org_name": "Seoul National University", "asn": "AS9488"},
    ])
    http = FakeHttp({"1.1.1.1": {"ports": [3306]}})
    findings, _ = check_exposure(http, index, min_severity="low")
    assert findings[0].org_id == "snu"
    assert findings[0].org_name == "Seoul National University"


def test_reports_risky_open_port_and_ignores_clean_ip_and_cves():
    # A risky open port is a fact and gets reported; an IP with no data yields
    # nothing; InternetDB `vulns` are version-inferred so they are not claimed.
    http = FakeHttp({"1.1.1.1": {"ports": [443, 3306], "vulns": ["CVE-2024-9"]}})
    index = build_ip_index([
        _asset("1.1.1.1", "db.x.com"),
        _asset("2.2.2.2", "ok.x.com"),  # not in records -> 404 -> nothing
    ])
    fs, _ = check_exposure(http, index, min_severity="low")
    assert ("exposed-service", "port-3306") in {(f.category, f.rule) for f in fs}
    assert not any(f.category == "known-cve" for f in fs)
    assert all("2.2.2.2" not in f.evidence for f in fs)


def test_resume_reuses_answers_and_records_new_ones():
    index = build_ip_index([_asset("1.1.1.1", "db.x.com"), _asset("2.2.2.2", "b.x.com")])
    http = FakeHttp({"2.2.2.2": {"ports": [6379]}})
    asked = []
    http.get_json = lambda url, _g=http.get_json: asked.append(url) or _g(url)
    recorded = {}
    findings, _ = check_exposure(
        http, index, min_severity="low",
        answers={"1.1.1.1": {"ports": [3306]}},
        on_answer=recorded.__setitem__,
    )
    assert [u.rsplit("/", 1)[-1] for u in asked] == ["2.2.2.2"]  # 1.1.1.1 reused
    assert recorded == {"2.2.2.2": {"ports": [6379]}}
    assert {f.rule for f in findings} == {"port-3306", "port-6379"}


def test_failed_query_is_reported_not_treated_as_clean():
    class Broken(FakeHttp):
        def get_json(self, url):
            raise TimeoutError("timed out")

    index = build_ip_index([_asset("1.1.1.1", "db.x.com")])
    recorded = {}
    findings, problems = check_exposure(
        Broken({}), index, min_severity="low", on_answer=recorded.__setitem__,
    )
    assert not findings
    assert recorded == {}  # not saved, so a resume asks again
    assert any("조회 실패" in p for p in problems)
