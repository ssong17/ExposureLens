from __future__ import annotations

from exposure_lens.collect.merge import merge_assets


def _a(org, host, url="", ip="", asn=""):
    return {"record_id": f"{org}_{host}", "org_id": org, "asset_type":
            ("endpoint" if url else "subdomain"), "host": host, "url": url,
            "resolved_ip": ip, "asn": asn}


def test_merge_unions_and_dedups():
    run1 = [_a("x", "a.x.com"), _a("x", "b.x.com")]
    run2 = [_a("x", "b.x.com"), _a("x", "c.x.com")]  # b overlaps, c is new
    merged = merge_assets(run1, run2)
    hosts = sorted(m["host"] for m in merged)
    assert hosts == ["a.x.com", "b.x.com", "c.x.com"]  # union, b not duplicated


def test_merge_backfills_empty_ip():
    run1 = [_a("x", "a.x.com", ip="")]          # unresolved first time
    run2 = [_a("x", "a.x.com", ip="1.2.3.4")]   # resolved on retry
    merged = merge_assets(run1, run2)
    assert len(merged) == 1
    assert merged[0]["resolved_ip"] == "1.2.3.4"  # backfilled from run2


def test_merge_keeps_existing_record_id():
    run1 = [_a("x", "a.x.com", ip="1.1.1.1")]
    run2 = [dict(_a("x", "a.x.com", ip="9.9.9.9"), record_id="DIFFERENT")]
    merged = merge_assets(run1, run2)
    assert merged[0]["record_id"] == "x_a.x.com"      # stable id preserved
    assert merged[0]["resolved_ip"] == "1.1.1.1"      # existing non-empty wins


def test_valid_host_rejects_empty_labels():
    from exposure_lens.collect.collector import _in_scope, _valid_host
    assert _valid_host("a.snu.ac.kr")
    assert not _valid_host("a..snu.ac.kr")   # empty label -> IDNA crash source
    assert not _valid_host(".snu.ac.kr")
    assert not _valid_host("snu.ac.kr.")
    assert not _in_scope("sub..socarcorp.kr", "socarcorp.kr")  # filtered before resolve
    assert _in_scope("sub.socarcorp.kr", "socarcorp.kr")


def test_merge_does_not_downgrade_observed_freshness():
    """A later run that simply failed to see the asset must not mark it stale."""
    run1 = [dict(_a("x", "a.x.com"), freshness="current")]
    run2 = [dict(_a("x", "a.x.com"), freshness="archived")]
    assert merge_assets(run1, run2)[0]["freshness"] == "current"


def test_merge_backfills_last_seen():
    run1 = [dict(_a("x", "a.x.com"), last_seen="")]
    run2 = [dict(_a("x", "a.x.com"), last_seen="2026-09-01")]
    assert merge_assets(run1, run2)[0]["last_seen"] == "2026-09-01"
