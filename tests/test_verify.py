"""Probe helpers: liveness label and the paths a scan finding implies."""
from __future__ import annotations

from exposure_lens.probe.verify import implied_probes, liveness_label


def _finding(**kw):
    base = dict(finding_id="F1", org_id="snu", asset_ref="A1", severity="high",
                category="sensitive-host", rule="host-vcs", host="git.snu.ac.kr",
                url="", evidence="git.snu.ac.kr")
    base.update(kw)
    return base


def test_liveness_label():
    assert liveness_label(0) == "unreachable"
    assert liveness_label(200) == "live"
    assert liveness_label(302) == "redirect"
    assert liveness_label(403) == "protected"


def test_implied_probes_for_git_host():
    urls = [u for u, *_ in implied_probes(_finding())]
    assert "https://git.snu.ac.kr/.git/config" in urls
    assert "https://git.snu.ac.kr/.git/HEAD" in urls


def test_implied_probes_for_endpoint_uses_exact_url():
    f = _finding(category="vcs-exposure", rule="path-vcs", host="a.snu.ac.kr",
                 url="https://a.snu.ac.kr/.git/config")
    urls = [u for u, *_ in implied_probes(f)]
    assert urls == ["https://a.snu.ac.kr/.git/config"]


def test_implied_probes_host_only_falls_back_to_root():
    f = _finding(rule="host-unknown-rule")  # no specific VERIFY_PROBES entry
    probes = implied_probes(f)
    assert probes and probes[0][0] == "https://git.snu.ac.kr/"
