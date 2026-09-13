from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .apex import discover_apex
from .collector import collect_org
from .config import AppConfig, OrgConfig, load_config
from .models import ApexCandidate, Asset, run_date
from .net import Http
from .output import write_jsonl, write_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exposure-lens",
        description="Public asset collector driven by an organization list.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="check the config file")
    validate.add_argument("--config", "-i", required=True)

    for name, help_text in (
        ("discover-apex", "find apex domains from organization names"),
        ("collect", "enumerate subdomains under discovered apexes"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--config", "-i", required=True)
        scope = p.add_mutually_exclusive_group(required=True)
        scope.add_argument("--org", help="a single org_id")
        scope.add_argument("--group", help="all enabled orgs in this group")
        scope.add_argument("--all-enabled", action="store_true", help="all enabled orgs")
        p.add_argument("--output", "-o", default="output", help="output root directory")
    return parser


def _select(app: AppConfig, args: argparse.Namespace) -> tuple[OrgConfig, ...]:
    if args.org:
        return (app.get_org(args.org),)
    if args.group:
        return app.get_group(args.group)
    return app.get_enabled()


def _make_http(app: AppConfig) -> Http:
    c = app.collector
    return Http(
        user_agent=c.user_agent,
        interval=c.request_interval_seconds,
        timeout=c.timeout_seconds,
        max_retries=c.max_retries,
        max_bytes=c.max_response_bytes,
        max_requests=c.max_requests,
    )


def _finish(out_dir: Path, title: str, problems: list[str], http: Http) -> int:
    write_summary(out_dir / "summary.md", title, problems)
    print(f"\nrequests {http.request_count} - output {out_dir}")
    for p in problems:
        print(f"warning: {p}", file=sys.stderr)
    return 0


def _run_discover_apex(app: AppConfig, args: argparse.Namespace) -> int:
    http = _make_http(app)
    out_dir = Path(args.output) / run_date()
    out_dir.mkdir(parents=True, exist_ok=True)
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
            print(f"  ... and {len(candidates) - 15} more")

    write_jsonl(all_candidates, out_dir / "apex.jsonl")
    return _finish(out_dir, f"apex discovery - {run_date()}", problems, http)


def _run_collect(app: AppConfig, args: argparse.Namespace) -> int:
    http = _make_http(app)
    out_dir = Path(args.output) / run_date()
    out_dir.mkdir(parents=True, exist_ok=True)
    all_assets: list[Asset] = []
    problems: list[str] = []

    for org in _select(app, args):
        assets, org_problems = collect_org(http, org, app.collector)
        all_assets.extend(assets)
        problems.extend(org_problems)

        apex_count = len({a.apex for a in assets})
        sub_count = sum(1 for a in assets if a.asset_type == "subdomain")
        print(
            f"\n{org.name} ({org.org_id}) - {len(assets)} assets "
            f"({apex_count} apex, {sub_count} subdomain)"
        )
        for a in assets[:20]:
            print(f"  {a.apex_confidence:<6} {a.host}")
        if len(assets) > 20:
            print(f"  ... and {len(assets) - 20} more")

    write_jsonl(all_assets, out_dir / "assets.jsonl")
    return _finish(out_dir, f"collection - {run_date()}", problems, http)


def _force_utf8() -> None:
    # Keep Korean/box output intact on Windows consoles (cp949).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    args = build_parser().parse_args(argv)
    try:
        app = load_config(args.config)
        if args.command == "validate":
            print(f"config valid: {len(app.orgs)} orgs")
            return 0
        if args.command == "discover-apex":
            return _run_discover_apex(app, args)
        if args.command == "collect":
            return _run_collect(app, args)
        return 2
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
