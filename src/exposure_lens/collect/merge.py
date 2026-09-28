"""Accumulating collect results across runs.

Public indexes fail differently on every run (crt.sh 502s, Wayback times out,
urlscan rate-limits), so the union of a few runs is the real coverage. That is
why accumulating is `collect`'s DEFAULT rather than a flag the operator has to
remember: every run folds into the existing file through this. `--fresh` opts
out and starts over.
"""
from __future__ import annotations

# Fields a later run may backfill when the earlier one came up empty.
BACKFILL_FIELDS = ("resolved_ip", "asn", "last_seen")


def asset_key(asset: dict) -> tuple[str, str, str, str]:
    return (
        asset.get("org_id", ""),
        asset.get("asset_type", ""),
        asset.get("host", ""),
        asset.get("url", ""),
    )


def merge_assets(existing: list[dict], new: list[dict]) -> list[dict]:
    """Union by (org, type, host, url), keeping the earlier row's identity.

    Existing rows keep their record_id/discovered_at so ids stay stable across
    runs; a later run only adds assets it did not have before, backfills empty
    fields, and upgrades freshness when the new run actually observed the asset.
    """
    merged = {asset_key(a): dict(a) for a in existing}
    for a in new:
        key = asset_key(a)
        current = merged.get(key)
        if current is None:
            merged[key] = dict(a)
            continue
        for field in BACKFILL_FIELDS:
            if not current.get(field) and a.get(field):
                current[field] = a[field]
        # "current" is evidence the asset was observed live; never let a later
        # run that merely failed to see it downgrade that.
        if a.get("freshness") == "current":
            current["freshness"] = "current"
    return list(merged.values())
