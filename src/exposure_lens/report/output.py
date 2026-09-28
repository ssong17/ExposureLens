"""JSONL readers/writers.

JSONL holds every discovered record. ``write_jsonl_atomic`` exists so a long
collect can checkpoint after every organization: the file on disk is always a
complete, valid result, never a half-written one, so an index that stalls or a
process that is interrupted costs only the org in flight.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Protocol


class Serializable(Protocol):
    def to_dict(self) -> dict[str, object]: ...


def _row_json(row) -> str:
    data = row.to_dict() if hasattr(row, "to_dict") else row
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def read_jsonl(path: str | Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(rows: list, path: str | Path) -> None:
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(_row_json(row))
            handle.write("\n")


def write_jsonl_atomic(rows: list, path: str | Path) -> None:
    """Write via a temp file and rename, so the target is never half-written.

    Used for per-org checkpoints during collect: being killed mid-write must not
    leave a truncated JSONL that the next stage then fails to parse.
    """
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    write_jsonl(rows, tmp)
    os.replace(tmp, path)


def write_summary(
    path: str | Path,
    title: str,
    problems: list[str],
    *,
    preamble: list[str] | None = None,
    command: str | None = None,
) -> None:
    lines = [f"# {title}", ""]
    if command:
        lines.extend(["> 실행 명령", "", "```", command, "```", ""])
    if preamble:
        lines.extend(preamble)
        lines.append("")
    if problems:
        lines.append("## Problems")
        lines.append("")
        lines.extend(f"- {p}" for p in problems)
    elif not preamble:
        lines.append("No problems.")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
