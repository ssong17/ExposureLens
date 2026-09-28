"""Markdown report builders.

The rule this module enforces: a summary shows EXPOSURES, and reachability is
context for them, not an entry of its own. An earlier run wrote 302 rows of
which 300 were reachability bullets, burying two real secret findings. So
reachability is rolled up into a single line and the per-severity lists are
capped. Every summary also opens with the exact command that produced it.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..core.models import SEVERITY_LEVELS, is_liveness, severity_rank
from ..scan.rules import category_label

# Bullets printed per severity group before the list is truncated. Everything
# stays in the JSONL; this only keeps the human-facing file readable.
MAX_BULLETS_PER_SEVERITY = 50

_FRESHNESS_LABEL = {"current": "현재", "archived": "과거"}

# Reachability states in plain Korean. The stored rule stays English
# ("live-redirect") for stable data; only the display is localized.
_REACH_KO = {
    "live": "접속됨",
    "protected": "인증필요",
    "redirect": "리다이렉트",
    "unreachable": "응답없음",
}
# Triage order for the reachability roll-up line.
_REACH_ORDER = ["live", "protected", "redirect", "unreachable"]


def _reach_ko(label: str) -> str:
    return _REACH_KO.get(label, label)


def org_labels(orgs) -> dict[str, dict]:
    """org_id -> {name, …} from config, for naming rows in a report."""
    return {
        o.org_id: {
            "name": o.name,
            "aliases": tuple(o.search_names),
            "seeds": tuple(o.seed_domains),
            "org_type": o.org_type,
        }
        for o in (orgs or ())
    }


def org_display(org_id: str, row_name: str = "", labels: dict | None = None) -> str:
    """The best available human name for an org_id.

    Prefers the name stamped on the record itself (so an old JSONL still reads
    correctly), then config, then the bare id.
    """
    if row_name:
        return row_name
    entry = (labels or {}).get(org_id) or {}
    return entry.get("name") or org_id


def _command_header(command: str | None) -> list[str]:
    """The lines that open every summary: the command that produced it."""
    if not command:
        return []
    return ["> 실행 명령", "", "```", command, "```", ""]


def org_legend_lines(
    org_ids, labels: dict | None = None, rows=None, findings=None
) -> list[str]:
    """A per-org table: id, name, and how many findings each carries.

    Kept deliberately small — `org_id | 이름 | 발견 | C | H | M | L`. Aliases and
    org_type were noise in the report; they live in config where they belong.
    ``findings`` supplies the counts; omit it for a naming-only table.
    """
    labels = labels or {}
    org_ids = [o for o in dict.fromkeys(org_ids) if o]
    if not org_ids:
        return []
    from_rows: dict[str, str] = {}
    for row in rows or ():
        oid, name = _attr(row, "org_id"), _attr(row, "org_name")
        if oid and name:
            from_rows.setdefault(oid, name)

    counted = findings is not None
    per: dict[str, Counter] = {}
    if counted:
        for f in findings:
            per.setdefault(_attr(f, "org_id"), Counter())[_attr(f, "severity")] += 1

    if counted:
        lines = ["## 기관", "", "| org_id | 이름 | 발견 | C | H | M | L |",
                 "|---|---|---|---|---|---|---|"]
    else:
        lines = ["## 기관", "", "| org_id | 이름 |", "|---|---|"]
    for org_id in sorted(org_ids):
        name = org_display(org_id, from_rows.get(org_id, ""), labels)
        if counted:
            c = per.get(org_id, Counter())
            lines.append(
                f"| `{org_id}` | {name} | {sum(c.values())} | {c['critical']} "
                f"| {c['high']} | {c['medium']} | {c['low']} |"
            )
        else:
            lines.append(f"| `{org_id}` | {name} |")
    return lines


def category_rollup_lines(findings: list) -> list[str]:
    """What KINDS of sensitive things were found, worst kind first."""
    if not findings:
        return []
    per: dict[str, Counter] = {}
    for f in findings:
        per.setdefault(_attr(f, "category"), Counter())[_attr(f, "severity")] += 1
    order = sorted(
        per.items(),
        key=lambda kv: (
            min(severity_rank(s) for s in kv[1]),  # worst severity in the group
            -sum(kv[1].values()),
        ),
    )
    lines = ["## 발견된 유형", "", "| 유형 | 건수 | 최고 심각도 | category |",
             "|---|---|---|---|"]
    for category, counts in order:
        worst = min(counts, key=severity_rank)
        lines.append(
            f"| {category_label(category)} | {sum(counts.values())} | {worst} "
            f"| `{category}` |"
        )
    return lines


def _attr(finding, name: str, default: str = "") -> str:
    if isinstance(finding, dict):
        return str(finding.get(name, default) or default)
    return str(getattr(finding, name, default) or default)


def split_liveness(findings: list) -> tuple[list, list]:
    """(exposure findings, reachability rows) — reported differently."""
    exposures = [f for f in findings if not is_liveness(f)]
    liveness = [f for f in findings if is_liveness(f)]
    return exposures, liveness


def liveness_rollup(liveness: list) -> str:
    """One line summarising reachability, in the order that matters for triage."""
    if not liveness:
        return ""
    # rule is "live-<label>"; label is what liveness_label() produced.
    counts = Counter(_attr(f, "rule").removeprefix("live-") for f in liveness)
    parts = [f"{_reach_ko(n)} {counts[n]}" for n in _REACH_ORDER if counts.get(n)]
    parts += [
        f"{_reach_ko(n)} {c}" for n, c in sorted(counts.items())
        if n not in _REACH_ORDER
    ]
    return f"접속 상태 {len(liveness)}건 — " + ", ".join(parts)


def _bullet(finding) -> str:
    tags = []
    label = _FRESHNESS_LABEL.get(_attr(finding, "freshness"))
    if label:
        tags.append(label)
    status = _attr(finding, "status")
    if status:
        tags.append(status)
    tag = f" [{' · '.join(tags)}]" if tags else ""
    kind = category_label(_attr(finding, "category"))
    target = _attr(finding, "url") or _attr(finding, "host")
    org = _attr(finding, "org_id")
    owner = f"`{org}` " if org else ""
    return f"- {owner}[{kind}]{tag} {target}  {_attr(finding, 'evidence')}"


def findings_summary_lines(
    title: str, findings: list, problems: list[str] | None = None,
    orgs=None, command: str | None = None,
) -> list[str]:
    labels = org_labels(orgs)
    exposures, liveness = split_liveness(findings)
    counts = Counter(_attr(f, "severity") for f in exposures)
    lines = [f"# {title}", ""]
    lines.extend(_command_header(command))
    lines.append(
        f"노출 {len(exposures)}건 — critical {counts['critical']}, "
        f"high {counts['high']}, medium {counts['medium']}, low {counts['low']}"
    )
    rollup = liveness_rollup(liveness)
    if rollup:
        lines.append("")
        lines.append(rollup)
        lines.append("")
        lines.append("_접속 상태 상세는 liveness JSONL 파일에 있다._")
    lines.append("")

    legend = org_legend_lines(
        [_attr(f, "org_id") for f in findings], labels, findings, exposures
    )
    if legend:
        lines.extend(legend)
        lines.append("")

    rollup_lines = category_rollup_lines(exposures)
    if rollup_lines:
        lines.extend(rollup_lines)
        lines.append("")

    for severity in SEVERITY_LEVELS:
        group = [f for f in exposures if _attr(f, "severity") == severity]
        if not group:
            continue
        lines.append(f"## {severity} ({len(group)})")
        lines.append("")
        lines.extend(_bullet(f) for f in group[:MAX_BULLETS_PER_SEVERITY])
        if len(group) > MAX_BULLETS_PER_SEVERITY:
            hidden = len(group) - MAX_BULLETS_PER_SEVERITY
            lines.append(f"- ... 외 {hidden}건 (전체는 JSONL 참고)")
        lines.append("")

    if not exposures:
        lines.append("노출 findings 없음.")
        lines.append("")
    if problems:
        lines.append("## Problems")
        lines.append("")
        lines.extend(f"- {p}" for p in problems)
        lines.append("")
    return lines


def write_findings_summary(
    path: str | Path, title: str, findings: list,
    problems: list[str] | None = None, orgs=None, command: str | None = None,
) -> None:
    lines = findings_summary_lines(title, findings, problems, orgs, command)
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect_stats_lines(assets: list[dict], orgs=None) -> list[str]:
    """Per-org counts for a collect summary, split by current vs archived."""
    labels = org_labels(orgs)
    per: dict[str, dict] = {}
    for a in assets:
        s = per.setdefault(
            a.get("org_id", ""),
            {"hosts": 0, "endpoints": 0, "ips": set(), "current": 0, "name": ""},
        )
        s["name"] = s["name"] or a.get("org_name", "")
        if a.get("asset_type") == "endpoint":
            s["endpoints"] += 1
        else:
            s["hosts"] += 1
        if a.get("resolved_ip"):
            s["ips"].add(a["resolved_ip"])
        if a.get("freshness") == "current":
            s["current"] += 1

    lines = [
        "## 수집 요약",
        "",
        "current = 지금 관측(urlscan 최근 / 호스트 해석됨), 과거 = Wayback에만",
        "",
        "| org_id | 기관 | 호스트 | 엔드포인트 | 해석 IP | current |",
        "|---|---|---|---|---|---|",
    ]
    t_host = t_ep = t_cur = 0
    t_ip: set[str] = set()
    for org_id in sorted(per):
        s = per[org_id]
        name = org_display(org_id, s["name"], labels)
        lines.append(
            f"| `{org_id}` | {name} | {s['hosts']} | {s['endpoints']} "
            f"| {len(s['ips'])} | {s['current']} |"
        )
        t_host += s["hosts"]
        t_ep += s["endpoints"]
        t_cur += s["current"]
        t_ip |= s["ips"]
    lines.append(
        f"| 합계 | | {t_host} | {t_ep} | {len(t_ip)} | {t_cur} |"
    )
    return lines


def print_findings(findings: list, printer, *, limit: int = 30) -> None:
    """Console preview: exposures first, ranked, reachability excluded."""
    exposures, liveness = split_liveness(findings)
    exposures = sorted(exposures, key=lambda f: severity_rank(_attr(f, "severity")))
    for f in exposures[:limit]:
        fresh = _FRESHNESS_LABEL.get(_attr(f, "freshness"), "")
        status = _attr(f, "status") or "-"
        printer(
            f"  {_attr(f, 'org_id')[:12]:<12} {_attr(f, 'severity'):<8} "
            f"{category_label(_attr(f, 'category')):<22} {fresh:<4} {status:<4} "
            f"{_attr(f, 'url') or _attr(f, 'evidence')}"
        )
    if len(exposures) > limit:
        printer(f"  ... 외 {len(exposures) - limit}건")
    rollup = liveness_rollup(liveness)
    if rollup:
        printer(f"  ({rollup})")
