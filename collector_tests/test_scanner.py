from __future__ import annotations

from exposure_lens.scan.scanner import _mask, scan_assets


def _asset(**kw) -> dict:
    base = {
        "record_id": "X_1",
        "org_id": "x",
        "asset_type": "endpoint",
        "host": "www.x.com",
        "url": "",
    }
    base.update(kw)
    return base


def test_host_rules_flag_sensitive_subdomains():
    assets = [
        _asset(record_id="H1", asset_type="subdomain", host="jenkins.x.com"),
        _asset(record_id="H2", asset_type="subdomain", host="dev.x.com"),
        _asset(record_id="H3", asset_type="subdomain", host="www.x.com"),
    ]
    findings = scan_assets(assets, min_severity="low")
    by_host = {f.host: f for f in findings}
    assert by_host["jenkins.x.com"].severity == "high"
    assert by_host["dev.x.com"].severity == "medium"
    assert "www.x.com" not in by_host


def test_path_rules_flag_sensitive_files():
    assets = [
        _asset(record_id="P1", host="a.x.com", url="https://a.x.com/.git/config"),
        _asset(record_id="P2", host="a.x.com", url="https://a.x.com/.env"),
        _asset(record_id="P3", host="a.x.com", url="https://a.x.com/index.html"),
    ]
    findings = scan_assets(assets, min_severity="low")
    cats = {f.asset_ref: (f.category, f.severity) for f in findings}
    assert cats["P1"] == ("vcs-exposure", "high")
    assert cats["P2"] == ("secret-file", "critical")
    assert "P3" not in cats


def test_secret_in_query_is_masked():
    url = "https://a.x.com/cb?api_key=SUPERSECRET123456"
    findings = scan_assets([_asset(host="a.x.com", url=url)], min_severity="low")
    secret = next(f for f in findings if f.category == "leaked-secret")
    assert secret.severity == "high"
    assert "SUPERSECRET123456" not in secret.evidence
    assert secret.evidence.startswith("api_key=")


def test_min_severity_filters_low():
    assets = [_asset(host="a.x.com", url="https://a.x.com/swagger/")]  # low
    assert scan_assets(assets, min_severity="low")
    assert not scan_assets(assets, min_severity="high")


def test_mask():
    assert _mask("SUPERSECRET123456") == "SUPE****56"
    assert _mask("short") == "sh****"
