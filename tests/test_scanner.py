from __future__ import annotations

from exposure_lens.core.models import FindingIds
from exposure_lens.scan.scanner import _mask, scan_assets, scan_body


def _asset(**kw) -> dict:
    base = {
        "record_id": "X_1",
        "org_id": "x",
        "asset_type": "endpoint",
        "host": "www.x.com",
        "url": "",
        "resolved_ip": "203.0.113.1",  # live by default; hosts stay full severity
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
    # Name-based host matches are candidates, capped at medium (verify promotes).
    assert by_host["jenkins.x.com"].severity == "medium"
    assert by_host["dev.x.com"].severity == "medium"
    assert "www.x.com" not in by_host


def test_dead_host_finding_is_downgraded():
    live = _asset(record_id="L", asset_type="subdomain", host="jenkins.x.com")
    dead = _asset(
        record_id="D", asset_type="subdomain", host="jenkins.y.com", resolved_ip=""
    )
    findings = scan_assets([live, dead], min_severity="low")
    by_host = {f.host: f for f in findings}
    assert by_host["jenkins.x.com"].severity == "medium"  # live candidate
    assert by_host["jenkins.y.com"].severity == "low"  # dead -> one notch down
    assert "dns-unresolved" in by_host["jenkins.y.com"].evidence


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


def _body(text: str):
    return scan_body(
        text, asset={"record_id": "R", "org_id": "x", "host": "h"},
        url="https://h/static/app.js", status="200", source="wayback-body",
        min_severity="low", next_id=FindingIds("T", date="20260101"),
    )


def test_client_rules_detect_authz_and_routes():
    fs = _body(
        'if(user.isAdmin){} const r="/api/v1/orders"; '
        '//# sourceMappingURL=app.js.map'
    )
    cats = {f.category for f in fs}
    assert {"client-authz", "api-endpoint", "sourcemap"} <= cats


def test_client_findings_are_not_masked():
    # A route/authz check keeps its literal value (masking would hide the point).
    fs = _body('fetch("/admin/users/delete")')
    api = next(f for f in fs if f.category == "api-endpoint")
    assert "/admin/users/delete" in api.evidence
    assert "****" not in api.evidence


def test_secrets_in_body_still_masked():
    fs = _body('const t="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";')
    sec = next(f for f in fs if f.category == "leaked-secret")
    assert "****" in sec.evidence
    assert "ABCDEFGHIJKLMNOP" not in sec.evidence
