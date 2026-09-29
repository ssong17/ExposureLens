from __future__ import annotations

from exposure_lens.core.models import FindingIds
from exposure_lens.scan.scanner import _mask, _mask_match, scan_assets, scan_body


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


# ---- scan_body: masking and severity floor (moved from test_inspect) ---------

def test_mask_match_keeps_key_hides_value():
    masked = _mask_match('password: "hunter2secret"')
    assert "hunter2secret" not in masked
    assert masked.startswith("password:")


def test_scan_body_detects_and_masks_multiple_categories():
    body = (
        'apiKey: "AKIAABCDEFGHIJKLMNOP"\n'
        'DATABASE_URL = "postgres://admin:s3cr3tpw@db.internal:5432/prod"\n'
        "resident 900101-1234567\n"
    )
    fs = _body(body)
    cats = {f.category for f in fs}
    assert {"leaked-secret", "db-exposure", "pii-exposure"} <= cats
    assert all("s3cr3tpw" not in f.evidence for f in fs)
    assert all("1234567" not in f.evidence for f in fs)


def test_scan_body_respects_min_severity():
    body = "resident 900101-1234567"  # high-severity pii rule
    ids = FindingIds("T", date="20260101")
    assert scan_body(
        body, asset={"record_id": "R", "host": "h"}, url="u", status="",
        source="wayback-body", min_severity="high", next_id=ids,
    )
    assert not scan_body(
        body, asset={"record_id": "R", "host": "h"}, url="u", status="",
        source="wayback-body", min_severity="critical", next_id=ids,
    )


# ---- path severity: evidence strength, not scary names -----------------------

def _endpoint(url, freshness="current", rid="E1"):
    return _asset(record_id=rid, asset_type="endpoint", url=url,
                  host=url.split("/")[2], freshness=freshness)


def _rules_for(url, **kw):
    return {(f.rule, f.severity) for f in scan_assets([_endpoint(url, **kw)],
                                                       min_severity="low")}


def test_plain_zip_download_is_not_a_backup():
    # Field runs: bid attachments and CI logo zips were all ranked high.
    assert not _rules_for("https://x.com/cgi-bin/attach_file/bid/20040407.Zip")
    assert not _rules_for("https://x.com/static/data/CI_Logo.zip")


def test_dump_in_a_page_name_is_not_a_db_dump():
    assert not _rules_for("https://x.com/bbs/dump-truck-hydraulic-system.html")
    assert not _rules_for("https://x.com/find-a-car/special-vehicle/dump")


def test_real_backup_shapes_still_match():
    assert ("path-db-dump", "high") in _rules_for("https://x.com/db.sql")
    assert ("path-backup-copy", "high") in _rules_for("https://x.com/index.php.bak")
    assert ("path-backup-archive", "high") in _rules_for("https://x.com/www_backup.zip")
    assert ("path-backup-archive", "high") in _rules_for("https://x.com/backups/2020.tgz")


def test_one_backup_finding_per_url():
    rules = _rules_for("https://x.com/backups/2020.tgz")
    assert rules == {("path-backup-archive", "high")}  # not also backup-dir


def test_wayback_only_path_is_a_notch_lower():
    assert ("path-vcs", "high") in _rules_for("https://x.com/.git/config")
    assert ("path-vcs", "medium") in _rules_for(
        "https://x.com/.git/config", freshness="archived")


def test_admin_route_is_surface_not_exposure():
    assert _rules_for("https://x.com/admin/") == {("path-admin", "low")}


def test_query_variants_of_one_path_collapse():
    assets = [
        _endpoint(f"https://x.com/admin/input.jsp?page={i}", rid=f"E{i}")
        for i in range(5)
    ]
    fs = scan_assets(assets, min_severity="low")
    assert len(fs) == 1
    assert "(+4 query variants)" in fs[0].evidence


def test_secret_in_archived_url_keeps_full_severity():
    # A credential sitting in a public archive is readable by anyone today.
    fs = scan_assets([_endpoint("https://x.com/a?x=AKIAABCDEFGHIJKLMNOP",
                                freshness="archived")], min_severity="low")
    assert ("secret-aws-akid", "critical") in {(f.rule, f.severity) for f in fs}


# ---- fix: case-sensitive structural rules (no lowercase false positives) -----

def test_structural_secret_rules_are_case_sensitive():
    ids = FindingIds("T", date="20260101")
    # A base64/hex blob containing "akia"/"eyj" must NOT read as a real key.
    noise = 'x = "zAkiA1bcd2Efg3hIjklm foo eyjABCDEFGH.zzzzzzzz.wwwwwwww"'
    assert not [f for f in scan_body(
        noise, asset={"record_id": "R", "org_id": "o", "host": "h"},
        url="u", status="", source="s", min_severity="low", next_id=ids)
        if f.category == "leaked-secret"]


def test_real_uppercase_aws_key_still_flagged():
    ids = FindingIds("T", date="20260101")
    fs = scan_body(
        'k="AKIAABCDEFGHIJKLMNOP"',
        asset={"record_id": "R", "org_id": "o", "host": "h"},
        url="u", status="", source="s", min_severity="low", next_id=ids)
    assert any(f.rule == "body-aws-akid" for f in fs)


# ---- fix: run-wide dedup of the same secret across bodies --------------------

def test_dedup_collapses_same_secret_across_bodies():
    ids = FindingIds("T", date="20260101")
    dedup: dict = {}
    body = 'api_key: "e0559a1b2c3d4e5f6a7b8c9d0e1f2a3b"'
    a = {"record_id": "R1", "org_id": "o", "host": "h"}
    first = scan_body(body, asset=a, url="p1", status="", source="s",
                      min_severity="low", next_id=ids, dedup=dedup)
    second = scan_body(body, asset=a, url="p2", status="", source="s",
                       min_severity="low", next_id=ids, dedup=dedup)
    assert len(first) == 1        # first body reports it
    assert second == []           # second body's copy is suppressed
    assert list(dedup.values())[0] == 2  # but counted


def test_dedup_keeps_different_orgs_separate():
    ids = FindingIds("T", date="20260101")
    dedup: dict = {}
    body = 'api_key: "e0559a1b2c3d4e5f6a7b8c9d0e1f2a3b"'
    f1 = scan_body(body, asset={"record_id": "R", "org_id": "a", "host": "h"},
                   url="u", status="", source="s", min_severity="low",
                   next_id=ids, dedup=dedup)
    f2 = scan_body(body, asset={"record_id": "R", "org_id": "b", "host": "h"},
                   url="u", status="", source="s", min_severity="low",
                   next_id=ids, dedup=dedup)
    assert len(f1) == 1 and len(f2) == 1  # same value, two orgs -> two findings
