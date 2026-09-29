"""Apex discovery: seed anchoring keeps same-named foreign orgs out."""
from __future__ import annotations

from exposure_lens.collect.discovery import _confidence
from exposure_lens.collect.tldclass import main_label
from exposure_lens.core.config import OrgConfig


def _org(**kw) -> OrgConfig:
    base = dict(org_id="snu", name="Seoul National University", org_type="school",
                enabled=True, seed_domains=("snu.ac.kr",))
    base.update(kw)
    return OrgConfig(**base)


def test_main_label():
    assert main_label("snu.ac.kr") == "snu"
    assert main_label("seoultech.ac.kr") == "seoultech"
    assert main_label("navercorp.com") == "navercorp"


def test_seed_match_is_high():
    org = _org()
    conf, ev = _confidence("snu.ac.kr", 40, 100, True, org, frozenset({"snu"}))
    assert conf == "high" and "seed_match" in ev


def test_sibling_institution_capped_at_low():
    # Same TLD class (school/.ac.kr), different main label -> not this org.
    org = _org()
    conf, ev = _confidence("seoultech.ac.kr", 8, 100, False, org, frozenset({"snu"}))
    assert conf == "low" and "unrelated_family" in ev


def test_related_family_can_be_medium():
    # Same 'snu' label and a school-class TLD (.re.kr = research) -> medium.
    org = _org(seed_domains=("snu.ac.kr",))
    conf, _ = _confidence("snu.re.kr", 5, 100, False, org, frozenset({"snu"}))
    assert conf == "medium"


def test_no_seed_keeps_tld_medium():
    # Without seeds we cannot anchor; TLD-class match still earns medium.
    org = _org(seed_domains=())
    conf, _ = _confidence("kaist.ac.kr", 5, 100, False, org, frozenset())
    assert conf == "medium"


def test_same_name_foreign_org_does_not_hijack():
    # 쏘카(socarcorp.kr) vs SOCAR oil (dominant .com.tr) — seeds present, foreign
    # family must NOT get high even if it dominates crt.sh.
    org = _org(org_id="socar", name="Socar", org_type="company",
               seed_domains=("socarcorp.kr",))
    labels = frozenset({"socarcorp"})
    conf, ev = _confidence("fleetassist.com.tr", 900, 1000, True, org, labels)
    assert conf == "low"  # dominant but unrelated family -> not hijacked
    # the real seed family still resolves high
    conf2, _ = _confidence("socarcorp.kr", 5, 1000, False, org, labels)
    assert conf2 == "high"
