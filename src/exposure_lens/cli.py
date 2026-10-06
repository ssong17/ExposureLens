"""Command-line entry point: argument parsing and stage orchestration only.

Report formatting lives in ``report.summary``, merge logic in ``collect.merge``,
the scan-stage body pass in ``scan.bodyscan`` and the probe stage in
``probe.prober``. This file wires them together.

Output layout: ``output/YYYYMMDD/<HHMMSS>_<stage>.jsonl`` and
``<HHMMSS>_<stage>_summary.md``. The time prefix makes each run's files easy to
tell apart; ``_latest_output`` globs for the newest so the next stage still
picks them up automatically. Every summary opens with the command that made it.

Config: a ``config/`` folder (one .toml per org + a shared collector file) is
used when present; otherwise the legacy single ``config.toml``.
"""
from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path

from .collect.discovery import discover_apex
from .collect.collector import collect_org
from .collect.merge import merge_assets
from .core.config import AppConfig, OrgConfig, load_config
from .core.models import (
    SEVERITY_LEVELS,
    SEVERITY_ORDER,
    ApexCandidate,
    run_date,
    run_time,
)
from .core.net import Http, NetworkDown
from .core.progress import (
    COLLECT_SUFFIX,
    SCAN_SUFFIX,
    CollectProgress,
    ScanProgress,
    find_latest,
    stamp_of,
)
from .report.output import (
    read_jsonl,
    write_jsonl,
    write_jsonl_atomic,
    write_summary,
)
from .report.summary import (
    collect_stats_lines,
    liveness_rollup,
    print_findings,
    write_findings_summary,
)
from .probe.prober import run_probe
from .scan.bodyscan import scan_archive_bodies
from .scan.scanner import scan_assets
from .scan.services import build_ip_index, check_exposure


def _default_config() -> str:
    """Prefer the config/ folder; fall back to the legacy single file."""
    return "config" if Path("config").is_dir() else "config.toml"


DEFAULT_CONFIG = _default_config()

# Exit code when a stage stopped because our connection dropped. Distinct from
# 2 (bad config/input) so a wrapper script can stop and tell the operator to
# rerun with --resume instead of marching on through every remaining org.
EXIT_NETWORK_DOWN = 3


def _latest_output(output_root: str, stage: str) -> str:
    """Newest ``<time>_<stage>.jsonl`` under the output root.

    Files are named ``<HHMMSS>_<stage>.jsonl`` inside ``output/YYYYMMDD/``, so
    sorting by (date dir, filename) descending gives the most recent run. The
    old fixed name (``<stage>.jsonl``) is still accepted for back-compat.
    """
    root = Path(output_root)
    cands = sorted(
        (p for p in root.glob(f"*/*_{stage}.jsonl") if p.is_file()),
        key=lambda p: (p.parent.name, p.name),
        reverse=True,
    )
    if cands:
        return str(cands[0])
    legacy = sorted(
        (p for p in root.glob(f"*/{stage}.jsonl") if p.is_file()),
        key=lambda p: p.parent.name,
        reverse=True,
    )
    if legacy:
        return str(legacy[0])
    raise ValueError(
        f"{stage} 결과를 {output_root}/ 아래에서 찾지 못했습니다. 먼저 "
        f"collect/scan을 실행하거나 --assets/--findings로 경로를 지정하세요."
    )


def _add_scope(parser: argparse.ArgumentParser, *, required: bool) -> None:
    scope = parser.add_mutually_exclusive_group(required=required)
    scope.add_argument("--org", help="a single org_id")
    scope.add_argument("--group", help="all enabled orgs in this group")
    scope.add_argument(
        "--all-enabled", action="store_true", help="all enabled orgs"
    )


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", "-o", default="output", help="output root directory")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="suppress progress logs"
    )


def _add_resume(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--resume", action="store_true",
        help="continue the newest run that broke off (network drop, Ctrl-C) "
        "from where it stopped, instead of starting over",
    )


def _add_vibe(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--no-vibe", dest="vibe", action="store_false",
        help="turn OFF AI site-builder fingerprinting (Lovable, v0, Replit, "
        "Base44, Manus, Claude). On by default; emits low-severity "
        "'vibe-platform' findings from host names and served bodies (shown only "
        "at --min-severity low, since platform attribution is not an exposure)",
    )


def _add_probe_options(parser: argparse.ArgumentParser, *, full: bool) -> None:
    """Options for the probe stage, shared by `probe` and `run --probe`.

    The apex-confidence floor is fixed at high (live fetches must never touch a
    host that might not be this org's), so there is no `--confidence` knob. The
    archived-body source now belongs to the `scan` stage, so there is no
    `--source` knob either — `probe` always fetches live. There is no volume cap
    (a run processes everything found and pauses between organizations instead).
    """
    if not full:
        return
    parser.add_argument(
        "--scripts", action="store_true",
        help="only read client-code endpoints (.js/.json/.map) for JS/authz rules",
    )
    parser.add_argument(
        "--only-findings", action="store_true",
        help="only read endpoints already flagged critical/high in --findings",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exposure-lens",
        description="Public asset collector driven by an organization list.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="check the config file/folder")
    validate.add_argument("--config", "-i", default=DEFAULT_CONFIG)

    run = sub.add_parser(
        "run",
        help="the whole pipeline: collect -> scan (add --probe for the live "
        "probe stage). Defaults to all enabled orgs.",
    )
    run.add_argument("--config", "-i", default=DEFAULT_CONFIG)
    _add_scope(run, required=False)
    run.add_argument(
        "--probe", action="store_true",
        help="also run the probe stage — identical to the `probe` command",
    )
    _add_probe_options(run, full=False)
    run.add_argument(
        "--no-services", action="store_true",
        help="skip the Shodan current-services check in the scan stage",
    )
    run.add_argument("--no-resolve", action="store_true", help="skip IP/ASN resolution")
    run.add_argument("--no-endpoints", action="store_true", help="skip Wayback endpoints")
    run.add_argument("--no-search", dest="search", action="store_false", help="turn OFF search-engine discovery (on by default; no-op anyway without a GOOGLE_API_KEY+GOOGLE_CSE_ID or BRAVE_SEARCH_API_KEY env var)")
    run.add_argument("--search-query", action="append", metavar="KW", help="search keyword/template to use with --search (repeatable). A bare keyword becomes site:apex \"KW\"; a value with {apex} is a full template. Overrides config search_queries")
    run.add_argument(
        "--no-archive-bodies", action="store_true",
        help="skip the scan stage's archived-body pass (Wayback). "
        "By default scan reads archived bodies to extract secrets/backend-config "
        "without touching the target; --probe then only confirms these live and "
        "fetches endpoints the archive lacked",
    )
    run.add_argument(
        "--fresh", action="store_true",
        help="discard the existing collect result instead of accumulating into it",
    )
    run.add_argument(
        "--min-severity", choices=list(SEVERITY_LEVELS), default="medium",
        help="lowest severity to report (default: medium)",
    )
    _add_resume(run)
    _add_vibe(run)
    _add_common(run)

    apex = sub.add_parser(
        "discover-apex", help="find apex domains from organization names"
    )
    apex.add_argument("--config", "-i", default=DEFAULT_CONFIG)
    _add_scope(apex, required=True)
    _add_common(apex)

    collect = sub.add_parser(
        "collect", help="enumerate subdomains under discovered apexes"
    )
    collect.add_argument("--config", "-i", default=DEFAULT_CONFIG)
    _add_scope(collect, required=True)
    collect.add_argument(
        "--no-resolve", action="store_true", help="skip IP/ASN resolution"
    )
    collect.add_argument(
        "--no-endpoints", action="store_true", help="skip Wayback endpoints"
    )
    collect.add_argument(
        "--no-search", dest="search", action="store_false", help="turn OFF search-engine discovery (on by default; no-op anyway without a GOOGLE_API_KEY+GOOGLE_CSE_ID or BRAVE_SEARCH_API_KEY env var)"
    )
    collect.add_argument(
        "--search-query", action="append", metavar="KW", help="search keyword/template to use with --search (repeatable). A bare keyword becomes site:apex \"KW\"; a value with {apex} is a full template. Overrides config search_queries"
    )
    collect.add_argument(
        "--fresh", action="store_true",
        help="discard the existing collect result and start over. The default is "
        "to accumulate (dedup), because crt.sh/Wayback fail differently every "
        "run and the union of a few runs is the real coverage",
    )
    _add_resume(collect)
    _add_common(collect)

    # scan = no-touch stage. Offline host/URL rules + current services (Shodan
    # InternetDB) + archived response bodies (Wayback). No request to the
    # target; findings and their summary come out together.
    scan = sub.add_parser(
        "scan",
        help="SCAN (no target contact): analyse collected assets — "
        "host/URL rules + current open services (Shodan InternetDB) + archived "
        "response bodies (Wayback).",
    )
    scan.add_argument("--config", "-i", default=DEFAULT_CONFIG)
    scan.add_argument(
        "--assets", "-a",
        help="collect JSONL to scan (default: the latest collect output)",
    )
    scan.add_argument(
        "--min-severity", choices=list(SEVERITY_LEVELS), default="medium",
        help="lowest severity to report (default: medium)",
    )
    scan.add_argument(
        "--no-services", action="store_true",
        help="skip the Shodan current-services check",
    )
    scan.add_argument(
        "--no-archive-bodies", action="store_true",
        help="skip the archived-body pass (Wayback). By default scan "
        "reads archived snapshots to extract secrets/backend-config the "
        "host/URL rules cannot see, without touching the target",
    )
    _add_resume(scan)
    _add_vibe(scan)
    _add_common(scan)

    # probe = the target-touching stage: live GET to the target.
    probe = sub.add_parser(
        "probe",
        help="PROBE: live-GET the target to check current exposure — endpoint "
        "bodies/JS + finding reachability + unauthenticated access. "
        "high-confidence apexes only.",
    )
    probe.add_argument("--config", "-i", default=DEFAULT_CONFIG)
    probe.add_argument(
        "--assets", "-a",
        help="collect JSONL (endpoints to read; default: latest collect)",
    )
    probe.add_argument(
        "--findings", "-f",
        help="scan JSONL whose findings to verify (default: latest scan)",
    )
    probe.add_argument(
        "--min-severity", choices=list(SEVERITY_LEVELS), default="low",
        help="lowest severity to report (default: low)",
    )
    _add_probe_options(probe, full=True)
    _add_vibe(probe)
    _add_common(probe)
    return parser


def _select(app: AppConfig, args: argparse.Namespace) -> tuple[OrgConfig, ...]:
    if getattr(args, "org", None):
        return (app.get_org(args.org),)
    if getattr(args, "group", None):
        return app.get_group(args.group)
    return app.get_enabled()


def _make_http(app: AppConfig, *, quiet: bool = False) -> Http:
    c = app.collector
    on_retry = None if quiet else (
        lambda m: print(f"  ~ {m}", file=sys.stderr, flush=True)
    )
    return Http(
        user_agent=c.user_agent,
        interval=c.request_interval_seconds,
        timeout=c.timeout_seconds,
        max_retries=c.max_retries,
        retry_delays=c.retry_delays_seconds,
        max_bytes=c.max_response_bytes,
        max_body_bytes=c.max_body_bytes,
        max_requests=c.max_requests,
        cache_entries=c.cache_entries,
        on_retry=on_retry,
    )


def _logger(quiet: bool):
    if quiet:
        return None
    return lambda m: print(m, file=sys.stderr, flush=True)


def _severity_breakdown(findings) -> str:
    """"critical N, high N, medium N, low N" — the count line every stage prints."""
    c = Counter(f.severity for f in findings)
    return (
        f"critical {c['critical']}, high {c['high']}, "
        f"medium {c['medium']}, low {c['low']}"
    )


def _report(
    out_dir: Path, http: Http | None, problems: list[str], *, code: int = 0
) -> int:
    reqs = f"requests {http.request_count} - " if http else ""
    print(f"\n{reqs}output {out_dir}")
    for p in problems:
        print(f"warning: {p}", file=sys.stderr)
    if code == EXIT_NETWORK_DOWN:
        print(
            "stopped: network down. Rerun the same command with --resume to "
            "continue from where it stopped.",
            file=sys.stderr,
        )
    return code


def _out_dir(args: argparse.Namespace) -> Path:
    path = Path(args.output) / run_date()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _adopt(args: argparse.Namespace, progress_path: Path, suffix: str) -> Path:
    """Continue a broken-off run: reuse its time stamp and date directory, so
    the resumed output overwrites that run's files instead of starting new ones."""
    args._stamp = stamp_of(progress_path, suffix)
    return progress_path.parent


def _resume_path(args: argparse.Namespace, suffix: str, stage: str) -> Path:
    path = find_latest(args.output, suffix)
    if path is None:
        raise ValueError(
            f"이어서 실행할 {stage} 작업이 {args.output}/ 아래에 없습니다 "
            f"(중단된 실행이 없음). --resume 없이 실행하세요."
        )
    return path


def _f(out_dir: Path, args: argparse.Namespace, name: str) -> Path:
    """Time-prefixed output path: output/YYYYMMDD/<HHMMSS>_<name>."""
    return out_dir / f"{args._stamp}_{name}"


def _run_discover_apex(app: AppConfig, args: argparse.Namespace) -> int:
    http = _make_http(app, quiet=args.quiet)
    out_dir = _out_dir(args)
    all_candidates: list[ApexCandidate] = []
    problems: list[str] = []

    for org in _select(app, args):
        candidates, errors = discover_apex(http, org)
        all_candidates.extend(candidates)
        if not candidates:
            problems.append(f"[{org.org_id}] no apex candidates")
        for err in errors:
            note = f"(kept {len(candidates)} candidates)" if candidates else ""
            problems.append(f"[{org.org_id}] source error {note}: {err}")

        highs = sum(1 for c in candidates if c.confidence == "high")
        print(f"\n{org.name} ({org.org_id}) - {len(candidates)} candidates, {highs} high")
        for c in candidates[:15]:
            print(f"  {c.confidence:<6} {c.apex:<28} {','.join(c.evidence)}")
        if len(candidates) > 15:
            print(f"  ... 외 {len(candidates) - 15}건")

    write_jsonl(all_candidates, _f(out_dir, args, "apex.jsonl"))
    write_summary(
        _f(out_dir, args, "apex_summary.md"), f"apex discovery - {run_date()}",
        problems, command=args._command_str,
    )
    return _report(out_dir, http, problems)


def _collect_stage(
    app: AppConfig, args: argparse.Namespace, http: Http, out_dir: Path,
) -> tuple[list[dict], list[str], bool]:
    """Collect every selected org, accumulating and checkpointing as we go.

    Returns (assets, problems, network_down). Accumulate by default (public
    indexes fail differently each run, so the union is the real coverage;
    ``--fresh`` opts out). Two checkpoints are kept: the collect JSONL after
    every org, and a progress file after every apex, which ``--resume`` reads to
    skip finished orgs/apexes. Rest ``org_pause_seconds`` between orgs —
    sequential-with-rest is what replaced the request cap, so a full run
    finishes without hammering the free-tier indexes into rate-limiting.
    """
    log = _logger(args.quiet)
    say = log or (lambda _: None)
    pause = app.collector.org_pause_seconds
    out_path = _f(out_dir, args, "collect.jsonl")
    progress_path = _f(out_dir, args, "collect.progress.json")
    problems: list[str] = []

    if getattr(args, "resume", False) and progress_path.exists():
        progress = CollectProgress.load(progress_path)
        source = out_path if out_path.exists() else Path(progress.base or out_path)
        accumulated = read_jsonl(source) if source.exists() else []
        started_with = 0
        say(
            f"이어서 수집: 완료 {len(progress.orgs_done)}개 기관 건너뜀, "
            f"진행 중이던 {len(progress.partial)}개 기관은 끊긴 곳부터"
        )
    else:
        accumulated = []
        base = ""
        if not args.fresh:
            try:
                base = _latest_output(args.output, "collect")
                accumulated = read_jsonl(base)
            except ValueError:
                accumulated = []
        progress = CollectProgress(progress_path, base=base)
        progress.save()
        started_with = len(accumulated)
    collected = 0
    down = False
    first = True

    orgs = _select(app, args)
    for org in orgs:
        if org.org_id in progress.orgs_done:
            continue
        # Rest between orgs (not before the first one this run touches).
        if pause > 0 and not first:
            say(f"  다음 기관까지 {pause:.0f}s 휴식...")
            time.sleep(pause)
        first = False

        state = progress.for_org(org.org_id)
        try:
            assets, org_problems = collect_org(
                http, org, app.collector,
                resolve=not args.no_resolve,
                endpoints=not args.no_endpoints,
                search=getattr(args, "search", True),
                search_queries=tuple(getattr(args, "search_query", None) or ()),
                log=log,
                progress=state,
                checkpoint=progress.save,
            )
        except NetworkDown as exc:
            progress.save()
            problems.append(f"[{org.org_id}] 네트워크 끊김으로 중단: {exc}")
            down = True
            break
        problems.extend(org_problems)
        collected += len(assets)
        accumulated = merge_assets(accumulated, [a.to_dict() for a in assets])
        write_jsonl_atomic(accumulated, out_path)  # checkpoint after each org
        if state.complete:
            progress.org_done(org.org_id)
        else:
            progress.save()  # a step was cut off: stays resumable

        sub_count = sum(1 for a in assets if a.asset_type in ("apex", "subdomain"))
        ep_count = sum(1 for a in assets if a.asset_type == "endpoint")
        ip_count = len({a.resolved_ip for a in assets if a.resolved_ip})
        print(
            f"\n{org.name} ({org.org_id}) - {len(assets)} assets "
            f"({sub_count} hosts, {ep_count} endpoints, {ip_count} IPs)"
        )
        for a in assets[:20]:
            if a.asset_type == "endpoint":
                print(f"  {a.apex_confidence:<6} endpoint {a.url}")
            else:
                print(f"  {a.apex_confidence:<6} {a.host} {a.resolved_ip} {a.asn}")
        if len(assets) > 20:
            print(f"  ... 외 {len(assets) - 20}건")

    if not down and not progress.partial:
        progress.finish()  # nothing left to resume
    elif not down:
        problems.append(
            f"연결 실패로 미완료 기관 {len(progress.partial)}개: "
            f"{', '.join(progress.partial)} (--resume 으로 이어서)"
        )
    if not args.fresh and started_with:
        problems.append(
            f"기존 collect에 누적: {started_with} + {collected} 수집 "
            f"-> {len(accumulated)} 고유 (--fresh 로 초기화)"
        )
    return accumulated, problems, down


def _run_collect(app: AppConfig, args: argparse.Namespace) -> int:
    http = _make_http(app, quiet=args.quiet)
    if args.resume:
        out_dir = _adopt(args, _resume_path(args, COLLECT_SUFFIX, "collect"), COLLECT_SUFFIX)
    else:
        out_dir = _out_dir(args)
    merged, problems, down = _collect_stage(app, args, http, out_dir)

    write_summary(
        _f(out_dir, args, "collect_summary.md"), f"collect - {run_date()}", problems,
        preamble=collect_stats_lines(merged, app.orgs), command=args._command_str,
    )
    return _report(out_dir, http, problems, code=EXIT_NETWORK_DOWN if down else 0)


def _scan_stage(
    app: AppConfig, args: argparse.Namespace, assets: list[dict], http: Http | None,
    progress: ScanProgress | None = None,
) -> tuple[list, list[str], set[str] | None]:
    """The scan stage: offline host/URL rules, plus (unless disabled) current
    open services (Shodan) and the archived-body pass (Wayback). Never touches
    the target.

    Returns ``(findings, problems, archive_missed)``. ``archive_missed`` is the
    set of endpoint URLs the archive had no snapshot for, which the ``probe``
    stage fetches live — or ``None`` when the archive pass did not run (then the
    probe stage reads every body). ``progress`` records each Shodan
    answer and each archived-body URL as they arrive and supplies the ones an
    interrupted run already got, so a resume only does the rest. A
    ``NetworkDown`` propagates.
    """
    findings = scan_assets(assets, min_severity=args.min_severity,
                           vibe=getattr(args, "vibe", False))
    problems: list[str] = []
    archive_missed: set[str] | None = None
    if not args.no_services and http is not None:
        print(
            "note: current-services check reads Shodan InternetDB (third-party "
            "scan data; never contacts the target).",
            file=sys.stderr,
        )
        svc, sprob = check_exposure(
            http, build_ip_index(assets),
            min_severity=args.min_severity, log=_logger(args.quiet),
            answers=progress.answers if progress else None,
            on_answer=progress.record if progress else None,
        )
        findings.extend(svc)
        problems.extend(sprob)
    if not getattr(args, "no_archive_bodies", False) and http is not None:
        print(
            "\nscan - reading archived snapshots (Wayback; never contacts the "
            "target)...",
            file=sys.stderr,
        )
        http.clear_cache()
        arch, missed, aprob = scan_archive_bodies(
            http, assets, min_severity=args.min_severity,
            vibe=getattr(args, "vibe", False), log=_logger(args.quiet),
            done=progress.arch if progress else None,
            done_missed=progress.arch_missed if progress else None,
            on_result=progress.record_archive if progress else None,
        )
        findings.extend(arch)
        problems.extend(aprob)
        archive_missed = set(missed)
        print(
            f"scan archive - {len(arch)} findings "
            f"({_severity_breakdown(arch)}); {len(archive_missed)} endpoints "
            f"had no snapshot"
        )
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings, problems, archive_missed


def _scan_needs_network(args: argparse.Namespace) -> bool:
    """True when the scan stage has a slow network path (Shodan or archive)."""
    return not args.no_services or not getattr(args, "no_archive_bodies", False)


def _start_scan_progress(
    args: argparse.Namespace, out_dir: Path, assets_path: str,
) -> ScanProgress | None:
    if not _scan_needs_network(args):
        return None  # offline rules only: nothing slow to resume
    return ScanProgress.start(_f(out_dir, args, "scan.progress.jsonl"), assets_path)


def _run_scan(app: AppConfig, args: argparse.Namespace) -> int:
    if args.resume:
        path = _resume_path(args, SCAN_SUFFIX, "scan")
        out_dir = _adopt(args, path, SCAN_SUFFIX)
        progress = ScanProgress.load(path)
        assets_path = args.assets or progress.assets_path
        print(
            f"이어서 scan: Shodan {len(progress.answers)}개 IP 응답 + "
            f"아카이브 {len(progress.arch)}개 URL 재사용",
            file=sys.stderr,
        )
    else:
        assets_path = args.assets or _latest_output(args.output, "collect")
        out_dir = _out_dir(args)
        progress = _start_scan_progress(args, out_dir, assets_path)
    assets = read_jsonl(assets_path)
    http = None if not _scan_needs_network(args) else _make_http(app, quiet=args.quiet)
    try:
        findings, problems, _missed = _scan_stage(app, args, assets, http, progress)
    except NetworkDown as exc:
        return _report(out_dir, http, [f"scan 중단: {exc}"], code=EXIT_NETWORK_DOWN)
    if progress:
        progress.finish()

    write_jsonl(findings, _f(out_dir, args, "scan.jsonl"))

    svc_n = sum(1 for f in findings if f.source == "shodan-internetdb")
    print(
        f"scanned {len(assets)} assets - {len(findings)} findings "
        f"({_severity_breakdown(findings)}; {svc_n} current-service)"
    )
    print_findings(findings, print)
    write_findings_summary(
        _f(out_dir, args, "scan_summary.md"), f"scan - {run_date()}", findings,
        problems, orgs=app.orgs, command=args._command_str,
    )
    return _report(out_dir, http, problems)


_LIVE_GET_NOTE = (
    "note: probe sends LIVE GETs to the target (high-confidence apexes only; "
    "one request per endpoint/path; no new-path guessing, no payloads)."
)


def _probe_stage(
    app: AppConfig, args: argparse.Namespace, http: Http,
    assets: list[dict], prior: list[dict],
    *, min_severity: str = "low", restrict_body_urls: set[str] | None = None,
):
    """The probe stage, shared by the `probe` command and `run --probe`."""
    print(_LIVE_GET_NOTE, file=sys.stderr)
    return run_probe(
        http, assets, prior,
        min_severity=min_severity,
        restrict_body_urls=restrict_body_urls,
        scripts_only=getattr(args, "scripts", False),
        only_findings=getattr(args, "only_findings", False),
        vibe=getattr(args, "vibe", False),
        log=_logger(args.quiet),
    )


def _write_probe_output(out_dir: Path, args, result, orgs=None) -> None:
    write_jsonl(result.findings, _f(out_dir, args, "probe.jsonl"))
    # Reachability is an asset property, not an exposure. Its own file is what
    # keeps hundreds of live-* rows from burying the real findings.
    write_jsonl(result.liveness, _f(out_dir, args, "liveness.jsonl"))
    write_findings_summary(
        _f(out_dir, args, "probe_summary.md"), f"probe - {run_date()}",
        result.rows, result.problems, orgs=orgs, command=args._command_str,
    )


def _run_probe(app: AppConfig, args: argparse.Namespace) -> int:
    assets = read_jsonl(args.assets or _latest_output(args.output, "collect"))
    try:
        prior = read_jsonl(args.findings or _latest_output(args.output, "scan"))
    except ValueError:
        prior = []

    http = _make_http(app, quiet=args.quiet)
    result = _probe_stage(
        app, args, http, assets, prior, min_severity=args.min_severity,
    )

    out_dir = _out_dir(args)
    _write_probe_output(out_dir, args, result, app.orgs)

    print(
        f"probed - {len(result.findings)} findings "
        f"({_severity_breakdown(result.findings)}; {len(result.confirmed)} confirmed)"
    )
    print_findings(result.rows, print, limit=40)
    return _report(out_dir, http, result.problems)


def _pipeline_probe_stage(
    app: AppConfig, args: argparse.Namespace, http: Http, out_dir: Path,
    assets: list[dict], scan_findings: list, archive_missed: set[str] | None,
    problems: list[str],
) -> None:
    """Probe pass in the pipeline: confirm the scan candidates live AND fetch the
    bodies the archive missed. When the archive pass ran, live body reads are
    restricted to its misses (no re-fetching what the scan archive pass already
    covered); with --no-archive-bodies there were no misses to track, so it reads
    all.
    """
    print("\nprobe - confirm scan candidates + fetch archive misses...")
    http.clear_cache()
    result = _probe_stage(
        app, args, http, assets, [f.to_dict() for f in scan_findings],
        min_severity=args.min_severity, restrict_body_urls=archive_missed,
    )
    _write_probe_output(out_dir, args, result, app.orgs)
    problems.extend(result.problems)
    print(
        f"probe - {len(result.findings)} findings, {len(result.confirmed)} confirmed"
    )
    print_findings(result.rows, print, limit=20)
    rollup = liveness_rollup(result.liveness)
    if rollup:
        print(f"  {rollup}")


def _run_pipeline(app: AppConfig, args: argparse.Namespace) -> int:
    """collect -> scan (-> probe) in one pass, wiring stages in memory.

    ``--resume`` continues whichever stage broke off last: an unfinished
    collect resumes and then scans; an unfinished scan skips collect entirely
    and reuses that run's collect output.
    """
    http = _make_http(app, quiet=args.quiet)
    scan_progress: ScanProgress | None = None
    if args.resume:
        cands = [
            (p, suffix)
            for p, suffix in (
                (find_latest(args.output, COLLECT_SUFFIX), COLLECT_SUFFIX),
                (find_latest(args.output, SCAN_SUFFIX), SCAN_SUFFIX),
            )
            if p is not None
        ]
        if not cands:
            _resume_path(args, COLLECT_SUFFIX, "run")  # raises the "nothing" error
        path, suffix = max(cands, key=lambda c: c[0].stat().st_mtime)
        out_dir = _adopt(args, path, suffix)
        if suffix == SCAN_SUFFIX:
            scan_progress = ScanProgress.load(path)
    else:
        out_dir = _out_dir(args)

    collect_path = _f(out_dir, args, "collect.jsonl")
    if scan_progress is not None:
        asset_dicts = read_jsonl(scan_progress.assets_path or collect_path)
        problems: list[str] = []
        print(f"collect - 완료된 결과 재사용 ({len(asset_dicts)} assets)")
    else:
        asset_dicts, problems, down = _collect_stage(app, args, http, out_dir)
        if down:
            write_summary(
                _f(out_dir, args, "run_summary.md"), f"run - {run_date()}", problems,
                preamble=collect_stats_lines(asset_dicts, app.orgs),
                command=args._command_str,
            )
            return _report(out_dir, http, problems, code=EXIT_NETWORK_DOWN)
        print(f"collect - {len(asset_dicts)} assets")
        # Write the collect summary now, before the long scan/archive/probe
        # stages. If one of those is later killed, this summary still exists
        # (previously only the final run_summary was written, so an interrupted
        # run left no summary at all).
        write_summary(
            _f(out_dir, args, "collect_summary.md"), f"collect - {run_date()}",
            problems, preamble=collect_stats_lines(asset_dicts, app.orgs),
            command=args._command_str,
        )
        scan_progress = _start_scan_progress(args, out_dir, str(collect_path))

    http.clear_cache()  # index pages are done with; do not carry them further
    try:
        findings, sproblems, archive_missed = _scan_stage(
            app, args, asset_dicts, http, scan_progress
        )
    except NetworkDown as exc:
        problems.append(f"scan 중단: {exc}")
        return _report(out_dir, http, problems, code=EXIT_NETWORK_DOWN)
    if scan_progress:
        scan_progress.finish()
    problems.extend(sproblems)

    write_jsonl(findings, _f(out_dir, args, "scan.jsonl"))  # full scan candidate set
    print(f"scan total - {len(findings)} findings ({_severity_breakdown(findings)})")
    print_findings(findings, print, limit=20)
    write_findings_summary(
        _f(out_dir, args, "scan_summary.md"), f"scan - {run_date()}", findings,
        problems, orgs=app.orgs, command=args._command_str,
    )

    if args.probe:
        _pipeline_probe_stage(
            app, args, http, out_dir, asset_dicts, findings, archive_missed, problems
        )

    write_summary(
        _f(out_dir, args, "run_summary.md"), f"run - {run_date()}", problems,
        preamble=collect_stats_lines(asset_dicts, app.orgs), command=args._command_str,
    )
    return _report(out_dir, http, problems)


def _force_utf8() -> None:
    # Keep Korean/box output intact on Windows consoles (cp949).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


_COMMANDS = {
    "run": _run_pipeline,
    "discover-apex": _run_discover_apex,
    "collect": _run_collect,
    "scan": _run_scan,
    "probe": _run_probe,
}


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw)
    # Stamp every output of this run with one time prefix, and record the exact
    # command so each summary can print it at the top.
    args._stamp = run_time()
    args._command_str = "exposure-lens " + " ".join(raw)
    try:
        app = load_config(args.config)
        if args.command == "validate":
            enabled = sum(1 for o in app.orgs if o.enabled)
            print(f"config valid: {len(app.orgs)} orgs, {enabled} enabled")
            return 0
        handler = _COMMANDS.get(args.command)
        if handler is None:
            return 2
        return handler(app, args)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
