"""Rule precision: a secret *shape* is not a secret."""
from __future__ import annotations

from exposure_lens.core.models import FindingIds
from exposure_lens.scan.scanner import (
    is_credible_secret,
    is_placeholder,
    scan_assets,
)

from _helpers import run_scan_body


def _body(text: str, min_severity: str = "low"):
    return run_scan_body(
        text, min_severity=min_severity,
        next_id=FindingIds("T", date="20260101"), source="fetch-body",
    )


def test_placeholder_values_are_rejected():
    for value in (
        "YOUR_API_KEY", "changeme123", "xxxxxxxxxxxx", "${API_TOKEN}",
        "{{secret}}", "test-token-value", "undefined", "placeholder",
    ):
        assert is_placeholder(value), value


def test_real_looking_key_is_not_a_placeholder():
    assert not is_placeholder("Qx7bR2mZk9Lp4TvN8sWc")


def test_generic_assignment_needs_entropy():
    # A quoted placeholder in a bundle must not become a finding.
    assert not _body('const c={apiKey:"YOUR_API_KEY_HERE"};')
    assert not _body('password: "password"')
    # A real-looking value still is one.
    hits = _body('const c={apiKey:"Qx7bR2mZk9Lp4TvN8sWc"};')
    assert any(f.category == "hardcoded-secret" for f in hits)


def test_structural_rules_bypass_the_entropy_gate():
    # AKIA/ghp_ prefixes are proof on their own, so they are never entropy-gated
    # even though the surrounding text looks like a sample.
    assert is_credible_secret("body-aws-akid", "AKIAABCDEFGHIJKLMNOP")
    hits = _body('// example: const k = "AKIAABCDEFGHIJKLMNOP";')
    assert any(f.rule == "body-aws-akid" for f in hits)


def test_matches_per_rule_are_capped():
    from exposure_lens.scan.rules import MAX_MATCHES_PER_RULE

    bundle = ";".join(f'fetch("/api/v1/route{i}")' for i in range(200))
    routes = [f for f in _body(bundle) if f.rule == "js-api-route"]
    assert 0 < len(routes) <= MAX_MATCHES_PER_RULE


def test_url_query_secret_placeholder_is_rejected():
    placeholder = [
        {"record_id": "E", "org_id": "x", "asset_type": "endpoint",
         "host": "a.x.com", "url": "https://a.x.com/cb?api_key=YOUR_API_KEY",
         "resolved_ip": "1.2.3.4"},
    ]
    assert not [
        f for f in scan_assets(placeholder, min_severity="low")
        if f.category == "leaked-secret"
    ]


def test_placeholder_matching_does_not_eat_real_secrets():
    """Substring matching would have discarded these; segment matching must not.

    A false negative here is the expensive direction: the tool exists to find
    the secret, and 'foo'/'abc' appear inside random keys all the time.
    """
    for value in (
        "Xk9foo2MzQ7pLv3T", "abc9Zq2Xr7Lm4Nv8", "K3yTestQ92mKzPw1",
        "sEcReTiveRandom42Xq",
    ):
        assert not is_placeholder(value), value


def test_trailing_counter_does_not_rescue_a_placeholder():
    assert is_placeholder("changeme123")
    assert is_placeholder("secret1")
    assert is_placeholder("YOUR_API_KEY_2")
