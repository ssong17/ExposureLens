from __future__ import annotations

from exposure_lens.apex import discover_apex
from exposure_lens.config import OrgConfig
from exposure_lens.tldclass import registrable_apex, tld_class
from exposure_lens.sources import crtsh


class StubHttp:
    """crt.sh 응답을 흉내 내는 네트워크 없는 스텁."""

    def __init__(self, records: list[dict]) -> None:
        self._records = records
        self.request_count = 0

    def get_json(self, url: str):
        self.request_count += 1
        return self._records


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
    top = candidates[0]
    assert top.apex == "snu.ac.kr"
    assert top.confidence == "high"  # seed 일치
    # 형제 학교는 medium 이하로 격리된다.
    sibling = next(c for c in candidates if c.apex == "other.ac.kr")
    assert sibling.confidence in {"medium", "low"}


def test_discover_apex_drops_cdn_noise():
    org = OrgConfig(org_id="x", name="X Corp", org_type="company", enabled=True)
    records = [_cert("cdn.cloudfront.net")] * 10 + [_cert("www.x.com")] * 5
    candidates, _ = discover_apex(StubHttp(records), org)
    apexes = {c.apex for c in candidates}
    assert "cloudfront.net" not in apexes
    assert "x.com" in apexes
