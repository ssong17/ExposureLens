"""Shared/CDN addresses must not be claimed as one org's exposure."""
from __future__ import annotations

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
            raise Exception("404")
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
