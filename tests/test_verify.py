"""Verification: liveness + known-exposure probes on scan findings."""
from __future__ import annotations

from exposure_lens.probe.verify import (
    _probe_targets,
    liveness_label,
    verify_findings,
)


class FakeHttp:
    def __init__(self, responses):
        self._r = responses  # url -> (status, body)
        self.request_count = 0
        self.max_requests = 1000

    def probe(self, url):
        self.request_count += 1
        status, body = self._r.get(url, (0, ""))
        return status, body, "text/html", ""


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


def test_probe_targets_for_git_host():
    urls = [u for u, *_ in _probe_targets(_finding())]
    assert "https://git.snu.ac.kr/.git/config" in urls
    assert "https://git.snu.ac.kr/.git/HEAD" in urls


def test_probe_targets_for_endpoint_uses_exact_url():
    f = _finding(category="vcs-exposure", rule="path-vcs", host="a.snu.ac.kr",
                 url="https://a.snu.ac.kr/.git/config")
    urls = [u for u, *_ in _probe_targets(f)]
    assert urls == ["https://a.snu.ac.kr/.git/config"]


def test_verify_confirms_reachable_git_config():
    http = FakeHttp({
        "https://git.snu.ac.kr/.git/config": (200, "[core]\nrepositoryformatversion = 0"),
        "https://git.snu.ac.kr/.git/HEAD": (404, ""),
    })
    assets = {"A1": {"record_id": "A1", "apex_confidence": "high"}}
    out, problems = verify_findings(http, [_finding()], assets, min_severity="low")
    confirmed = [f for f in out if f.source == "verify-confirmed"]
    live = [f for f in out if f.category == "liveness"]
    assert any(f.url.endswith("/.git/config") for f in confirmed)
    assert live  # liveness always recorded
    assert not problems


def test_verify_confidence_gate_skips_medium():
    http = FakeHttp({})
    assets = {"A1": {"record_id": "A1", "apex_confidence": "medium"}}
    out, problems = verify_findings(http, [_finding()], assets, confidence="high")
    assert out == []
    assert any("confidence" in p for p in problems)
    assert http.request_count == 0  # never touched the target


def test_verify_records_liveness_for_dead_host():
    http = FakeHttp({})  # everything returns status 0
    assets = {"A1": {"record_id": "A1", "apex_confidence": "high"}}
    out, _ = verify_findings(http, [_finding()], assets, min_severity="low")
    assert out and all(f.category == "liveness" for f in out)
    assert all("unreachable" in f.evidence for f in out)
