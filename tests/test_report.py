"""Reporting: exposures are the report, reachability is context."""
from __future__ import annotations

from exposure_lens.core.models import Finding
from exposure_lens.report.summary import (
    MAX_BULLETS_PER_SEVERITY,
    category_rollup_lines,
    findings_summary_lines,
    liveness_rollup,
    org_legend_lines,
    split_liveness,
)


def _f(severity="high", category="leaked-secret", rule="body-aws-akid", **kw):
    base = dict(
        finding_id="P_1", org_id="x", asset_ref="A", severity=severity,
        category=category, rule=rule, host="h", url="https://h/a",
        evidence="e", discovered_at="t",
    )
    base.update(kw)
    return Finding(**base)


def _live(label="live"):
    return _f(severity="low", category="liveness", rule=f"live-{label}",
              evidence=f"200 {label}")


def test_liveness_is_split_out():
    rows = [_f(), _live(), _live("unreachable")]
    exposures, liveness = split_liveness(rows)
    assert len(exposures) == 1
    assert len(liveness) == 2


def test_liveness_never_becomes_bullets():
    # The regression this guards: 300 liveness rows buried 2 real findings.
    rows = [_f()] + [_live("http-404") for _ in range(300)]
    lines = findings_summary_lines("t", rows)
    body = "\n".join(lines)
    assert "접속 상태 300건" in body
    assert "[접속 상태]" not in body     # never a bullet
    assert "유출된 자격증명" in body


def test_liveness_rollup_orders_by_triage_value():
    rollup = liveness_rollup(
        [_live("unreachable"), _live("live"), _live("protected")]
    )
    assert rollup.index("접속됨 1") < rollup.index("인증필요 1")
    assert rollup.index("인증필요 1") < rollup.index("응답없음 1")


def test_medium_low_lists_are_capped():
    # medium/low are candidates/noise -> capped to keep the file readable.
    rows = [_f(severity="medium", category="admin-panel", rule="path-admin",
               url=f"https://h/{i}") for i in range(MAX_BULLETS_PER_SEVERITY + 10)]
    body = "\n".join(findings_summary_lines("t", rows))
    assert "외 10건" in body


def test_critical_high_lists_are_never_capped():
    # a leaked credential must never vanish past a bullet cap.
    rows = [_f(url=f"https://h/{i}") for i in range(MAX_BULLETS_PER_SEVERITY + 10)]
    body = "\n".join(findings_summary_lines("t", rows))
    assert body.count("[유출된 자격증명]") == MAX_BULLETS_PER_SEVERITY + 10
    assert "외 " not in body


def test_freshness_tag_is_rendered():
    body = "\n".join(findings_summary_lines("t", [_f(freshness="current")]))
    assert "[현재]" in body


# ---- org identity -------------------------------------------------------------

class _Org:
    def __init__(self, org_id, name, search_names=(), org_type="company"):
        self.org_id, self.name = org_id, name
        self.search_names, self.org_type = search_names, org_type
        self.seed_domains = ()


def test_bullets_name_the_owning_org():
    body = "\n".join(findings_summary_lines("t", [_f(org_id="snu")]))
    assert "`snu` [유출된 자격증명]" in body


def test_legend_resolves_org_id_to_name():
    # Aliases/type were dropped from the table; the config name still resolves.
    orgs = (_Org("snu", "Seoul National University", ("서울대학교", "SNU")),)
    body = "\n".join(findings_summary_lines("t", [_f(org_id="snu")], orgs=orgs))
    assert "| `snu` | Seoul National University |" in body
    assert "서울대학교" not in body  # aliases no longer clutter the report


def test_legend_falls_back_to_the_name_on_the_row():
    """An org dropped from config still reads correctly from an old JSONL."""
    rows = [_f(org_id="gone", org_name="Retired Org")]
    body = "\n".join(findings_summary_lines("t", rows))
    assert "| `gone` | Retired Org |" in body


def test_legend_is_empty_without_orgs():
    assert org_legend_lines([], {}) == []


# ---- what kind of thing was found ---------------------------------------------

def test_bullets_name_the_kind_not_the_slug():
    """`[backup-exposure]` tells a reader nothing; the finding IS the kind."""
    body = "\n".join(findings_summary_lines("t", [_f(category="backup-exposure")]))
    assert "[백업·덤프 파일]" in body
    assert "[backup-exposure]" not in body


def test_category_rollup_lists_kinds_worst_first():
    rows = [
        _f(severity="low", category="api-endpoint"),
        _f(severity="low", category="api-endpoint"),
        _f(severity="critical", category="db-exposure"),
    ]
    lines = category_rollup_lines(rows)
    body = "\n".join(lines)
    assert "DB 접속정보" in body and "API 경로" in body
    assert body.index("DB 접속정보") < body.index("API 경로")  # worst kind first
    assert "| API 경로 | 2 | low | `api-endpoint` |" in body


def test_rollup_keeps_the_raw_slug_for_grepping():
    body = "\n".join(category_rollup_lines([_f(category="pii-exposure")]))
    assert "`pii-exposure`" in body


def test_unknown_category_falls_back_to_its_slug():
    body = "\n".join(findings_summary_lines("t", [_f(category="brand-new-thing")]))
    assert "[brand-new-thing]" in body


# ---- per-org counts -----------------------------------------------------------

def test_legend_counts_findings_per_org():
    rows = [
        _f(org_id="snu", severity="critical"),
        _f(org_id="snu", severity="low"),
        _f(org_id="kaist", severity="high"),
        _live(),  # liveness must not inflate anyone's count
    ]
    body = "\n".join(findings_summary_lines("t", rows))
    assert "| `snu` | snu | 2 | 1 | 0 | 0 | 1 |" in body
    assert "| `kaist` | kaist | 1 | 0 | 1 | 0 | 0 |" in body


def test_legend_without_findings_has_no_count_columns():
    lines = org_legend_lines(["snu"], {})
    assert "발견" not in "\n".join(lines)
