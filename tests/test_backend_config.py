"""Front-end config parsing (Notion ASM item #1).

Real recon repeatedly pulls the app's own backend address and custom auth
scheme out of a shipped JS bundle — hancom's BACKEND_API_URL / X-HC-API-KEY was
the clearest case. The generic secret rules never caught these: a `*_URL` key is
not in the assignment rule, and a URL value must stay verbatim (masking it to
`https://ww****om` destroys the finding). These tests pin that gap.
"""
from __future__ import annotations

from exposure_lens.core.models import FindingIds
from exposure_lens.scan.scanner import scan_body


def _body(text: str, min_severity: str = "low"):
    return scan_body(
        text,
        asset={"record_id": "R", "org_id": "x", "org_name": "X", "host": "h"},
        url="https://h/_next/static/chunks/main.js",
        status="200",
        source="fetch-body",
        min_severity=min_severity,
        next_id=FindingIds("P"),
        freshness="current",
    )


def test_backend_base_url_is_captured_verbatim():
    fs = _body('{"BACKEND_API_URL":"https://www-api.hancom.com"}')
    hit = next(f for f in fs if f.rule == "js-backend-url")
    assert hit.category == "backend-config"
    # The address is the finding; it must not be masked.
    assert "https://www-api.hancom.com" in hit.evidence
    assert "****" not in hit.evidence


def test_various_backend_key_names_match():
    for key in ("STORE_API_URL", "API_URL", "SERVER_HOST", "AUTH_ENDPOINT",
                "BASE_URL", "GATEWAY_URL"):
        fs = _body(f'{{"{key}":"https://svc.example.com/base"}}')
        assert any(f.rule == "js-backend-url" for f in fs), key


def test_custom_auth_header_names_match():
    fs = _body('r.headers["X-HC-API-KEY"]=k;r.headers["X-HC-CLIENT-ID"]=c;')
    headers = [f for f in fs if f.rule == "js-custom-auth-header"]
    assert len(headers) == 2
    assert all(f.category == "backend-config" for f in headers)


def test_standard_headers_are_not_flagged():
    # These ship in every app and say nothing about a custom auth scheme.
    for header in ("X-Frame-Options", "X-Requested-With", "X-CSRF-Token",
                   "X-Content-Type-Options", "X-XSS-Protection"):
        fs = _body(f'h["{header}"]="v";')
        assert not any(f.category == "backend-config" for f in fs), header


def test_analytics_and_cdn_urls_are_not_backend_config():
    # GA/GTM/CDN script srcs are not the app's own backend.
    noise = (
        'img.src="https://www.google-analytics.com/collect";'
        'load("https://www.googletagmanager.com/gtm.js");'
        'const c="https://cdn.jsdelivr.net/npm/pkg";'
    )
    assert not any(f.category == "backend-config" for f in _body(noise))


def test_backend_url_needs_a_real_url_value():
    # A key that looks right but whose value is not an http(s) URL must not match
    # (avoids matching `apiUrl: state.apiUrl` style references).
    fs = _body('{"API_URL": config.apiUrl, "API_HOST": "${HOST}"}')
    assert not any(f.rule == "js-backend-url" for f in fs)


def test_backend_config_survives_min_severity_high():
    # js-backend-url is medium, so a high floor drops it — confirms severity wiring.
    assert _body('{"BACKEND_API_URL":"https://a.b.com"}', min_severity="medium")
    assert not [
        f for f in _body('{"BACKEND_API_URL":"https://a.b.com"}', min_severity="high")
        if f.category == "backend-config"
    ]
