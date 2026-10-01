"""Vibe-coding platform fingerprints (opt-in --vibe)."""
from __future__ import annotations

from exposure_lens.core.models import FindingIds
from exposure_lens.scan.scanner import scan_assets, scan_body
from exposure_lens.scan.vibe_rules import detect_body, detect_host


def test_domain_signature_matches_host():
    assert any(s.platform == "lovable" for s in detect_host("myapp.lovable.app"))
    assert any(s.platform == "replit" for s in detect_host("x.replit.app"))
    assert detect_host("www.example.com") == []


def test_body_signature_single_and_all():
    assert any(s.name == "v0_credit" for s in detect_body("<p>Built with v0</p>"))
    # analytics_pair needs BOTH substrings (match: all)
    assert not any(s.name == "lovable_analytics_pair" for s in detect_body("/~flock.js only"))
    assert any(s.name == "lovable_analytics_pair"
               for s in detect_body("/~flock.js and /~api/analytics"))


def test_scan_assets_vibe_flag_emits_platform_finding():
    asset = {"record_id": "R", "org_id": "o", "asset_type": "subdomain",
             "host": "app.lovable.app", "resolved_ip": "1.2.3.4", "freshness": "current"}
    off = scan_assets([asset], min_severity="low", vibe=False)
    on = scan_assets([asset], min_severity="low", vibe=True)
    assert not any(f.category == "vibe-platform" for f in off)
    assert any(f.category == "vibe-platform" and f.severity == "low" for f in on)


def test_scan_body_vibe_flag_emits_from_body():
    ids = FindingIds("T", date="20260101")
    fs = scan_body("<html>Made with Manus</html>",
                   asset={"record_id": "R", "org_id": "o", "host": "h"},
                   url="https://h/", status="200", source="fetch-body",
                   min_severity="low", next_id=ids, vibe=True)
    assert any(f.category == "vibe-platform" and "manus" in f.evidence for f in fs)
