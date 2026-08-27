from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from .config import load_config
from .passive import PassiveCollector
from .pipeline import write_jsonl, write_run_summary

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exposure-lens",
        description="검증된 기업 공식 공개 자산의 URL 후보를 제한적으로 수집합니다.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="설정 파일을 검사합니다.")
    validate.add_argument("--config", required=True)

    collect = subparsers.add_parser("collect", help="한 기업의 URL 후보를 수집합니다.")
    collect.add_argument("--config", required=True)
    scope = collect.add_mutually_exclusive_group(required=True)
    scope.add_argument("--company", help="설정의 company_id")
    scope.add_argument("--group", help="설정의 groups 값에 해당하는 활성 기업을 순차 실행")
    scope.add_argument("--all-enabled", action="store_true", help="모든 활성 기업을 순차 실행")
    collect.add_argument(
        "--output",
        default="output",
        help="날짜별 결과 폴더를 생성할 상위 경로 (기본값: output)",
    )
    collect.add_argument("--dry-run", action="store_true", help="HTTP 요청 없이 실행 계획만 표시")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        app = load_config(args.config)
        if args.command == "validate":
            print(f"설정 유효: 기업 {len(app.companies)}개")
            return 0

        if args.company:
            companies = (app.get_company(args.company),)
        elif args.group:
            companies = app.get_group(args.group)
        else:
            companies = app.get_enabled_companies()

        if args.dry_run:
            summaries = [
                PassiveCollector(app, company).dry_run_summary()
                for company in companies
            ]
            print(json.dumps(summaries, ensure_ascii=False, indent=2))
            return 0

        run_date = datetime.now().astimezone().strftime("%Y%m%d")
        output = Path(args.output) / run_date
        output.mkdir(parents=True, exist_ok=True)
        for company in companies:
            collector = PassiveCollector(app, company)
            candidates = collector.collect()
            destination = output / f"{company.company_id}.jsonl"
            write_jsonl(candidates, destination)
            queries_destination = output / f"{company.company_id}_site_queries.md"
            queries_destination.write_text(
                "# site: 검색 쿼리\n\n"
                + "\n".join(f"- `{query}`" for query in collector.search_queries)
                + "\n",
                encoding="utf-8",
            )
            print(
                f"수집 완료: {company.name}, 후보 {len(candidates)}개, "
                f"공개 색인 요청 {collector.request_count}회, 출력 {destination}"
            )
            for error in collector.errors:
                print(f"경고: {error}", file=sys.stderr)
        summary_path = output / "summary.md"
        write_run_summary(companies, summary_path)
        print(f"대상 기업 요약: {summary_path}")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
