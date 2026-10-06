"""The ``probe`` stage: read what the LIVE target serves.

``probe`` is the tool's one target-touching stage: it sends live GETs to the
target to check CURRENT exposure, where ``scan`` only has the URL/host name and
archived snapshots. The body-reading engine itself lives in ``scan.bodyscan``
(the ``scan`` stage owns it); here it is driven in FETCH mode and combined with
finding verification.

``run_probe`` is the one entry point. It folds both halves of the probe work
together:

  1. endpoint bodies -> secrets / config / DB / PII / client-code surface,
     following a source map when one is referenced;
  2. verification of existing scan findings -> reachability and known-exposure
     paths answering unauthenticated.

Both the ``probe`` command and ``run --probe`` call it, so the two can no longer
disagree about what ``probe`` does.

Safety gates, all enforced in the engine rather than at the call sites:
- live fetches only for high-confidence apexes, so we never touch a host that
  might belong to another organization;
- one GET per URL, redirects not followed, no payloads, no path guessing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..core.models import SEVERITY_ORDER, Finding, FindingIds, is_liveness
from ..core.net import Http
from ..scan.bodyscan import FETCH, annotate_duplicates, read_bodies
from ..scan.rules import base_severity
from .verify import verify_findings

# Confidence floor for the probe stage: live fetches touch the target, so only
# high-confidence apexes are ever probed. Fixed, no longer operator-tunable.
PROBE_CONFIDENCE = "high"


@dataclass
class ProbeResult:
    """What one probe pass produced, with reachability kept separate."""

    findings: list[Finding] = field(default_factory=list)
    liveness: list[Finding] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    # Endpoint URLs the archive had no snapshot for (filled by the scan stage's
    # archive pass). The probe pass fetches these live to cover what scan missed.
    missed: list[str] = field(default_factory=list)

    @property
    def rows(self) -> list[Finding]:
        return [*self.findings, *self.liveness]

    @property
    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.source == "verify-confirmed"]


def run_probe(
    http: Http,
    assets: list[dict],
    prior_findings: list[dict] | None = None,
    *,
    min_severity: str = "low",
    max_targets: int = 0,  # 0 = unlimited
    scripts_only: bool = False,
    only_findings: bool = False,
    restrict_body_urls: set[str] | None = None,
    vibe: bool = False,
    log: Callable[[str], None] | None = None,
) -> ProbeResult:
    """The whole probe stage: live body reads + finding verification.

    One ``FindingIds`` allocator is shared by both halves, so ids are unique
    across the run.

    ``restrict_body_urls`` (when not None) limits body reads to exactly those
    URLs — the pipeline passes the scan stage's archive misses here so a live
    pass reads only what the archive could not see.
    """
    prior_findings = prior_findings or []
    next_id = FindingIds("P")
    result = ProbeResult()
    # One dedup map for the whole pass: a secret in a shared template is counted
    # per org, reported once (see scan_body). Shared by body reads and
    # verification so a value seen by both is not emitted twice.
    dedup: dict[tuple[str, str, str], int] = {}

    if restrict_body_urls is not None:
        finding_urls: set[str] | None = restrict_body_urls
    elif only_findings:
        finding_urls = {
            f.get("url", "") for f in prior_findings
            # base_severity: an archived .git path scanned as a medium
            # candidate is exactly what this pass exists to check.
            if f.get("url") and base_severity(f) in ("critical", "high")
        }
    else:
        finding_urls = None

    # 1) endpoint bodies -> secrets/config/DB/PII/JS/authz (+ liveness)
    rows, problems = read_bodies(
        http, assets, source=FETCH, min_severity=min_severity,
        finding_urls=finding_urls, max_targets=max_targets,
        scripts_only=scripts_only, next_id=next_id, dedup=dedup,
        vibe=vibe, log=log,
    )
    result.problems.extend(problems)

    # 2) scan findings -> reachability + known-exposure paths + unauth access.
    # Verification always sends live requests, and the probe confidence floor
    # is fixed at high (we never probe a host that might not be this org's).
    if prior_findings:
        assets_by_id = {a.get("record_id", ""): a for a in assets}
        ver, vproblems = verify_findings(
            http, prior_findings, assets_by_id, min_severity=min_severity,
            confidence=PROBE_CONFIDENCE, max_targets=max_targets,
            next_id=next_id, dedup=dedup, vibe=vibe, log=log,
        )
        rows.extend(ver)
        result.problems.extend(vproblems)

    rows = annotate_duplicates(rows, dedup)
    suppressed = sum(n - 1 for n in dedup.values() if n > 1)
    if suppressed:
        result.problems.append(
            f"같은 시크릿이 여러 페이지에 반복돼 {suppressed}건을 합쳤습니다 "
            f"(finding당 '(+N pages)'로 표시)"
        )
    for row in rows:
        (result.liveness if is_liveness(row) else result.findings).append(row)
    result.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return result
