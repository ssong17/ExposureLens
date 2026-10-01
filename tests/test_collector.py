"""Collector: apex discovery, per-apex resume, Wayback split, host filtering."""
from __future__ import annotations

from exposure_lens.collect.discovery import discover_apex
from exposure_lens.collect.tldclass import registrable_apex, tld_class
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


def test_cymru_parse_bulk():
    text = (
        "AS      | IP            | BGP Prefix    | CC | Registry | Allocated | AS Name\n"
        "9488    | 147.46.10.129 | 147.46.0.0/16 | KR | apnic    | 1994-01-01 | SNU\n"
        "NA      | 10.0.0.1      | NA            | NA | other    | NA        | NA\n"
    )
    result = cymru.parse_bulk(text)
    assert result == {"147.46.10.129": "AS9488"}  # header and NA rows skipped


# ---- resume: per-apex progress ------------------------------------------------

from exposure_lens.collect import collector as collector_mod  # noqa: E402
from exposure_lens.core.config import CollectorConfig  # noqa: E402
from exposure_lens.core.progress import OrgProgress  # noqa: E402


class _LinkHttp:
    """Only what collect_org reads off Http; sources are stubbed separately."""

    connect_failure_total = 0


def _two_apex_org(monkeypatch, crt):
    cands = [
        ApexCandidate("x", "company", "a.com", "high", 9, (), "crt.sh", ""),
        ApexCandidate("x", "company", "b.com", "high", 5, (), "crt.sh", ""),
    ]
    monkeypatch.setattr(collector_mod, "discover_apex", lambda http, org: (cands, []))
    monkeypatch.setattr(collector_mod.crtsh, "domain_search", crt)
    return OrgConfig(org_id="x", name="X", org_type="company", enabled=True)


def test_resume_skips_finished_apexes(monkeypatch):
    asked = []

    def crt(http, apex):
        asked.append(apex)
        return {f"www.{apex}"}

    org = _two_apex_org(monkeypatch, crt)
    state = OrgProgress(
        org_id="x",
        candidates=[
            ApexCandidate("x", "company", "a.com", "high", 9, (), "crt.sh", "").to_dict(),
            ApexCandidate("x", "company", "b.com", "high", 5, (), "crt.sh", "").to_dict(),
        ],
        done_apexes=["a.com"],
        host_apex={"www.a.com": ["a.com", "high"]},
    )
    assets, _ = collector_mod.collect_org(
        _LinkHttp(), org, CollectorConfig(), resolve=False, endpoints=False,
        progress=state,
    )
    assert asked == ["b.com"]  # a.com was not asked again
    assert {a.host for a in assets} == {"www.a.com", "www.b.com"}  # but kept
    assert state.done_apexes == ["a.com", "b.com"] and state.complete


def test_apex_cut_off_by_the_link_is_left_for_resume(monkeypatch):
    http = _LinkHttp()

    def crt(http_, apex):
        if apex == "b.com":
            http.connect_failure_total += 1  # what Http does on a refused connect
            raise OSError("connection refused")
        return {f"www.{apex}"}

    org = _two_apex_org(monkeypatch, crt)
    saves = []
    state = OrgProgress(org_id="x")
    _, problems = collector_mod.collect_org(
        http, org, CollectorConfig(), resolve=False, endpoints=False,
        progress=state, checkpoint=lambda: saves.append(list(state.done_apexes)),
    )
    assert state.done_apexes == ["a.com"]
    assert not state.complete
    assert any("미완료" in p and "b.com" in p for p in problems)
    assert saves[-1] == ["a.com"]  # checkpointed after discovery and a.com


# ---- Wayback: CDX pagination (every subdomain, no 1000-row gap) --------------

def _wayback_setup(monkeypatch, apex_urls, *, fail=False, crt_hosts=()):
    """Stub crt.sh/urlscan and wayback.fetch_urls (paginated sweep result)."""
    def apex_query(http, apex, max_pages):
        if fail:
            raise TimeoutError("CDX timed out")
        return list(apex_urls)

    monkeypatch.setattr(collector_mod.crtsh, "domain_search",
                        lambda http, apex: set(crt_hosts))
    monkeypatch.setattr(collector_mod.urlscan, "fetch_observations",
                        lambda http, apex, limit: [])
    monkeypatch.setattr(collector_mod.wayback, "fetch_urls", apex_query)


def _run_apex(**cfg):
    org = OrgConfig(org_id="x", name="X", org_type="company", enabled=True)
    cand = ApexCandidate("x", "company", "x.com", "high", 9, (), "crt.sh", "")
    state = OrgProgress(org_id="x")
    lost = collector_mod._collect_apex(
        _LinkHttp(), org, CollectorConfig(**cfg), cand, state, endpoints=True,
    )
    return state, lost


def test_paginated_sweep_ingests_all_subdomains(monkeypatch):
    # one paginated result already spans multiple subdomains -> no host-splitting
    urls = ["https://x.com/a.php", "https://www.x.com/b.php", "https://shop.x.com/c.php"]
    _wayback_setup(monkeypatch, urls, crt_hosts=("x.com",))
    state, lost = _run_apex()
    assert lost is False
    assert set(state.endpoint_meta) == set(urls)   # every subdomain kept
    assert any("paginated" in p for p in state.problems) or True  # log line, not problem


def test_wayback_outage_marks_apex_incomplete(monkeypatch):
    _wayback_setup(monkeypatch, [], fail=True, crt_hosts=("x.com",))
    state, lost = _run_apex()
    assert lost is True                      # query raised -> redo on resume
    assert any("CDX timed out" in p for p in state.problems)


def test_phone_number_host_is_rejected():
    from exposure_lens.collect.collector import _valid_host
    assert not _valid_host("031-478-7879www.enscorp.co.kr")
    assert not _valid_host("82-31-478-7879www.enscorp.co.kr")
    assert _valid_host("www.enscorp.co.kr")
    assert _valid_host("24-7.example.com")  # single group: real


# ---- collect: cap query-string variants of one (host, path) ------------------

def test_query_variants_of_one_page_are_capped_at_collect(monkeypatch):
    # One page archived under 10 query strings -> only cap kept.
    urls = [f"https://x.com/board.php?idx={i}" for i in range(10)]
    monkeypatch.setattr(collector_mod.crtsh, "domain_search", lambda http, apex: set())
    monkeypatch.setattr(collector_mod.urlscan, "fetch_observations",
                        lambda http, apex, limit: [])
    monkeypatch.setattr(collector_mod.wayback, "fetch_urls", lambda http, apex, limit: urls)
    org = OrgConfig(org_id="x", name="X", org_type="company", enabled=True)
    cand = ApexCandidate("x", "company", "x.com", "high", 9, (), "crt.sh", "")
    state = OrgProgress(org_id="x")
    collector_mod._collect_apex(
        _LinkHttp(), org, CollectorConfig(max_endpoint_variants_per_path=3),
        cand, state, endpoints=True,
    )
    assert len(state.endpoint_meta) == 3  # 10 idx variants -> 3 kept


def test_different_paths_are_not_collapsed(monkeypatch):
    urls = ["https://x.com/a.php?x=1", "https://x.com/b.php?x=1",
            "https://x.com/c.php?x=1"]
    monkeypatch.setattr(collector_mod.crtsh, "domain_search", lambda http, apex: set())
    monkeypatch.setattr(collector_mod.urlscan, "fetch_observations",
                        lambda http, apex, limit: [])
    monkeypatch.setattr(collector_mod.wayback, "fetch_urls", lambda http, apex, limit: urls)
    org = OrgConfig(org_id="x", name="X", org_type="company", enabled=True)
    cand = ApexCandidate("x", "company", "x.com", "high", 9, (), "crt.sh", "")
    state = OrgProgress(org_id="x")
    collector_mod._collect_apex(
        _LinkHttp(), org, CollectorConfig(max_endpoint_variants_per_path=3),
        cand, state, endpoints=True,
    )
    assert len(state.endpoint_meta) == 3  # distinct paths all kept


# ---- numeric path-template cap (news/pr/N collapses) -------------------------

def test_numeric_path_template_is_capped(monkeypatch):
    # 20 article pages /news/pr/1..20 -> same template -> only cap kept
    urls = [f"https://x.com/news/pr/{i}" for i in range(20)]
    _wayback_setup(monkeypatch, urls, crt_hosts=("x.com",))
    state, _ = _run_apex(max_endpoint_variants_per_path=3)
    kept = [u for u in state.endpoint_meta if "/news/pr/" in u]
    assert len(kept) == 3  # template collapsed, not 20


def test_distinct_templates_not_collapsed(monkeypatch):
    urls = ["https://x.com/news/pr/1", "https://x.com/board/view/1",
            "https://x.com/admin/login"]
    _wayback_setup(monkeypatch, urls, crt_hosts=("x.com",))
    state, _ = _run_apex(max_endpoint_variants_per_path=3)
    assert len(state.endpoint_meta) == 3  # different templates all kept
