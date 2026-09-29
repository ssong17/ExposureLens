"""Firebase/Supabase surface + Google-key false-positive split (Notion item #2).

Every field report either hunted Firebase config or tripped over a Google
Analytics AIza key mistaken for a leaked secret. Two calls follow from that:
  - an AIza key is a public browser key (GA/Maps/Firebase) — record it low, and
    never let an apiKey/secret assignment around it promote it to high;
  - the real backend surface (Firebase bucket/db, Supabase URL) is worth medium.
"""
from __future__ import annotations

from exposure_lens.core.models import FindingIds
from exposure_lens.scan.scanner import is_credible_secret
from _helpers import run_scan_body


def _body(text: str, min_severity: str = "low"):
    return run_scan_body(
        text, min_severity=min_severity, next_id=FindingIds("P"),
        source="fetch-body", freshness="current",
    )


AIZA = "AIza" + "x" * 35  # exact Google browser-key length (39)


def test_ga_key_is_low_surface_not_a_leaked_secret():
    fs = _body(f"gtag('config','{AIZA}');")
    hit = next(f for f in fs if f.rule == "body-google-api")
    assert hit.severity == "low"
    assert hit.category == "backend-config"
    assert not any(f.category == "leaked-secret" for f in fs)


def test_aiza_wrapped_in_apikey_does_not_become_high():
    # The regression this guards: apiKey:"AIza…" was flagged high by the generic
    # assignment rule, undoing the deliberate low ranking.
    fs = _body(f'{{"apiKey":"{AIZA}"}}')
    assert not any(f.severity in ("high", "critical") for f in fs)
    assert any(f.rule == "body-google-api" for f in fs)


def test_recaptcha_site_key_is_not_a_credential():
    site_key = "6Le" + "y" * 37  # exact reCAPTCHA site-key length (40)
    assert not is_credible_secret("body-assigned-secret",
                                  f'RECAPTCHA_SITE_KEY:"{site_key}"')


def test_a_real_random_secret_still_ranks_high():
    fs = _body('const c={secretKey:"Xk9bR2mZq7pLv3TnW8sYc4uD"};')
    hit = next(f for f in fs if f.category == "hardcoded-secret")
    assert hit.severity == "high"


def test_firebase_bucket_and_db_are_surfaced():
    fs = _body(
        'databaseURL:"https://myapp.firebaseio.com",'
        'storageBucket:"myapp.appspot.com"'
    )
    rules = {f.rule for f in fs}
    assert "js-firebase-config" in rules
    assert all(
        f.category == "backend-config"
        for f in fs if f.rule == "js-firebase-config"
    )


def test_supabase_endpoint_is_surfaced():
    fs = _body('createClient("https://xyzcompanyabc.supabase.co","anon")')
    hit = next(f for f in fs if f.rule == "js-supabase")
    assert hit.category == "backend-config"
    assert "supabase.co" in hit.evidence
