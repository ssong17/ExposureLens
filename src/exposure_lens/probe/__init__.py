"""Probe stage: live-GET the target (read live bodies + verify findings).

The body-reading engine itself lives in ``scan.bodyscan`` (the scan stage owns
it); this package drives it in live-fetch mode and adds verification.
"""
