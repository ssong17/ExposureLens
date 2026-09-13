from __future__ import annotations

from exposure_lens.apex.discovery import discover_apex
from exposure_lens.apex.tldclass import registrable_apex, tld_class
from exposure_lens.collect.collector import _is_endpoint, select_target_apexes
from exposure_lens.core.config import OrgConfig
from exposure_lens.core.models import ApexCandidate
from exposure_lens.sources import crtsh, cymru


class StubHttp:
    """Network-free stub returning canned JSON for any URL."""

    def __init__(self, payload) -> None:
        self._payload = payload
        self.request_count = 0

    def get_json(self, url: str):
        self.request_count += 1
        return self._payload


def _cert(common_name: str) -> dict:
    return {"common_name": common_name, "name_value": "Example Org"}


def test_registrable_apex_handles_kr_two_level():
    assert registrable_apex("portal.snu.ac.kr") == "snu.ac.kr"
    assert registrable_apex("www.naver.com") == "naver.com"
    assert registrable_apex("a.b.c.go.kr") == "c.go.kr"


def test_tld_class():
    assert tld_class("mofa.go.kr") == "gov"
    assert tld_class("snu.ac.kr") == "school"
    assert tld_class("navercorp.com") == "company"
    assert tld_class("redcross.or.kr") == "nonprofit"


def test_hosts_of_excludes_org_name_strings():
    hosts = crtsh.hosts_of({"common_name": "*.snu.ac.kr", "name_value": "Seoul Nat Univ"})
    assert hosts == {"snu.ac.kr"}


def test_discover_apex_ranks_and_scores():
    org = OrgConfig(
        org_id="snu",
        name="Seoul National University",
        org_type="school",
        enabled=True,
        seed_domains=("snu.ac.kr",),
    )
    records = [_cert("portal.snu.ac.kr")] * 30 + [_cert("sibling.other.ac.kr")] * 3
    candidates, errors = discover_apex(StubHttp(records), org)

    assert not errors
    assert candidates[0].apex == "snu.ac.kr"
    assert candidates[0].confidence == "high"
    sibling = next(c for c in candidates if c.apex == "other.ac.kr")
    assert sibling.confidence in {"medium", "low"}


def test_discover_apex_drops_cdn_noise():
    org = OrgConfig(org_id="x", name="X Corp", org_type="company", enabled=True)
    records = [_cert("cdn.cloudfront.net")] * 10 + [_cert("www.x.com")] * 5
    candidates, _ = discover_apex(StubHttp(records), org)
    apexes = {c.apex for c in candidates}
    assert "cloudfront.net" not in apexes
    assert "x.com" in apexes


def test_select_target_apexes_keeps_high_medium_within_limit():
    cands = [
        ApexCandidate("o", "company", "a.com", "high", 100, (), "crt.sh", ""),
        ApexCandidate("o", "company", "b.com", "medium", 50, (), "crt.sh", ""),
        ApexCandidate("o", "company", "c.com", "low", 10, (), "crt.sh", ""),
    ]
    picked = select_target_apexes(cands, limit=5)
    assert [c.apex for c in picked] == ["a.com", "b.com"]
    assert select_target_apexes(cands, limit=1)[0].apex == "a.com"


def test_is_endpoint_skips_static_media():
    assert _is_endpoint("https://x.com/api/config.json")
    assert _is_endpoint("https://x.com/app.js")
    assert not _is_endpoint("https://x.com/logo.png")


def test_cymru_asn_parsing():
    payload = {"Answer": [{"data": '"23576 | 1.208.0.0/13 | KR | apnic | 2011-02-01"'}]}
    assert cymru.asn_of(StubHttp(payload), "1.2.3.4") == "AS23576"
    assert cymru.asn_of(StubHttp(payload), "not-an-ip") == ""
