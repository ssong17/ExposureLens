"""Resume state for long stages: what is already done, so a rerun skips it.

A progress file sits next to the stage's output while the stage is running and
is deleted when it finishes, so its presence alone means "this run broke off".
``--resume`` finds the newest one and continues it under the same time stamp.

- collect: ``<HHMMSS>_collect.progress.json`` — orgs finished, plus the org in
  flight down to the apex (its discovered candidates and what the finished
  apexes produced). Rewritten atomically after every apex.
- scan: ``<HHMMSS>_scan.progress.jsonl`` — a header naming the assets file,
  then one line per Shodan IP answered AND one line per archived-body URL read
  (its findings + whether the archive had a snapshot). Append-only, so an
  interrupted write loses at most the last line, and both slow network paths
  (Shodan current-services and the Wayback archive-body pass) resume.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

COLLECT_SUFFIX = "_collect.progress.json"
SCAN_SUFFIX = "_scan.progress.jsonl"


def find_latest(output_root: str | Path, suffix: str) -> Path | None:
    """Newest ``<date>/<time><suffix>`` under the output root, else None."""
    cands = sorted(
        (p for p in Path(output_root).glob(f"*/*{suffix}") if p.is_file()),
        key=lambda p: (p.parent.name, p.name),
        reverse=True,
    )
    return cands[0] if cands else None


def stamp_of(path: Path, suffix: str) -> str:
    """The ``HHMMSS`` prefix a progress file shares with its run's outputs."""
    return path.name[: -len(suffix)]


@dataclass
class OrgProgress:
    """How far one org's collection got before the run broke off."""

    org_id: str
    candidates: list[dict] = field(default_factory=list)
    discovery_errors: list[str] = field(default_factory=list)
    done_apexes: list[str] = field(default_factory=list)
    # host -> [apex, confidence]
    host_apex: dict[str, list[str]] = field(default_factory=dict)
    # url -> [apex, confidence, host, endpoint_source, last_seen]
    endpoint_meta: dict[str, list[str]] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    # Set False by collect_org when a step (discovery, an apex, DNS) was cut
    # off by a connection failure; such steps are left undone for resume.
    complete: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OrgProgress":
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


@dataclass
class CollectProgress:
    """Orgs fully collected, plus partial state for orgs that were not.

    An org stays in ``partial`` both when the run was killed mid-org and when
    it finished with a step cut off by the connection; either way a resume
    redoes only its unfinished steps.
    """

    path: Path
    # The earlier collect file this run accumulates into (reloaded on resume
    # when the run broke off before its own first checkpoint).
    base: str = ""
    orgs_done: list[str] = field(default_factory=list)
    partial: dict[str, OrgProgress] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "CollectProgress":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            path=path,
            base=str(data.get("base", "")),
            orgs_done=list(data.get("orgs_done", [])),
            partial={
                k: OrgProgress.from_dict(v) for k, v in data.get("partial", {}).items()
            },
        )

    def for_org(self, org_id: str) -> OrgProgress:
        """The saved partial state for this org, or a fresh one."""
        if org_id not in self.partial:
            self.partial[org_id] = OrgProgress(org_id=org_id)
        return self.partial[org_id]

    def save(self) -> None:
        data = {
            "base": self.base,
            "orgs_done": self.orgs_done,
            "partial": {k: v.to_dict() for k, v in self.partial.items()},
        }
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)

    def org_done(self, org_id: str) -> None:
        if org_id not in self.orgs_done:
            self.orgs_done.append(org_id)
        self.partial.pop(org_id, None)
        self.save()

    def finish(self) -> None:
        self.path.unlink(missing_ok=True)


class ScanProgress:
    """Append-only log of the scan stage's two slow network paths.

    ``answers`` holds Shodan records (ip -> record, None = no data); ``arch``
    holds the archived-body pass's per-URL result (url -> finding dicts) plus a
    separate ``arch_missed`` set of URLs the archive had no snapshot for. A
    resume reuses both, so neither the Shodan queries nor the Wayback reads are
    repeated.
    """

    def __init__(self, path: Path, assets_path: str = "") -> None:
        self.path = path
        self.assets_path = assets_path
        self.answers: dict[str, dict | None] = {}
        self.arch: dict[str, list[dict]] = {}
        self.arch_missed: set[str] = set()

    @classmethod
    def start(cls, path: Path, assets_path: str) -> "ScanProgress":
        progress = cls(path, assets_path)
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps({"assets": assets_path}, ensure_ascii=False) + "\n")
        return progress

    @classmethod
    def load(cls, path: Path) -> "ScanProgress":
        progress = cls(path)
        with path.open(encoding="utf-8") as handle:
            for i, line in enumerate(handle):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue  # the line being written when the run was killed
                if i == 0 and "assets" in row:
                    progress.assets_path = row["assets"]
                elif "ip" in row:
                    progress.answers[row["ip"]] = row.get("data")
                elif "arch" in row:
                    url = row["arch"]
                    progress.arch[url] = row.get("findings", [])
                    if row.get("missed"):
                        progress.arch_missed.add(url)
        return progress

    def record(self, ip: str, data: dict | None) -> None:
        self.answers[ip] = data
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps({"ip": ip, "data": data}, ensure_ascii=False) + "\n")

    def record_archive(self, url: str, findings: list[dict], missed: bool) -> None:
        """Persist one archived-body URL's result (replayed on resume)."""
        self.arch[url] = findings
        if missed:
            self.arch_missed.add(url)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(
                {"arch": url, "findings": findings, "missed": missed},
                ensure_ascii=False,
            ) + "\n")

    def finish(self) -> None:
        self.path.unlink(missing_ok=True)
