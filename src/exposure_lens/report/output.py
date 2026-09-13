"""JSONL and summary writers.

JSONL holds every discovered record. summary.md is a run report that lists only
problems (failures, capped runs); successful counts stay on stdout.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol


class Serializable(Protocol):
    def to_dict(self) -> dict[str, object]: ...


def read_jsonl(path: str | Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(rows: list[Serializable], path: str | Path) -> None:
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row.to_dict(), ensure_ascii=False, separators=(",", ":")))
            handle.write("\n")


def write_summary(path: str | Path, title: str, problems: list[str]) -> None:
    lines = [f"# {title}", ""]
    if problems:
        lines.append("## Problems")
        lines.append("")
        lines.extend(f"- {p}" for p in problems)
    else:
        lines.append("No problems.")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
