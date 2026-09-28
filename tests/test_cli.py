"""CLI wiring: stage selection, checkpointing, and report wiring."""
from __future__ import annotations

import json

import pytest

from exposure_lens import cli
from exposure_lens.core.models import Asset
from exposure_lens.report.output import read_jsonl

CONFIG = """
[collector]
request_interval_seconds = 0
max_requests = 50
org_pause_seconds = 0

[[orgs]]
org_id = "x"
name = "X"
org_type = "company"
enabled = true
"""

ORG_B = """
[[orgs]]
org_id = "y"
name = "Y"
org_type = "company"
enabled = true
"""


def _config(tmp_path, extra: str = "") -> str:
    path = tmp_path / "config.toml"
    path.write_text(CONFIG + extra, encoding="utf-8")
    return str(path)


def _asset(host: str, org: str = "x") -> Asset:
    return Asset(
        record_id=f"R_{host}", org_id=org, apex="x.com", apex_confidence="high",
        asset_type="subdomain", host=host, source="t", discovered_at="t",
        resolved_ip="1.2.3.4", freshness="current",
    )


@pytest.fixture
def no_network(monkeypatch):
    """Collect returns canned assets; nothing leaves the process."""
    calls: list[str] = []

    def fake_collect(http, org, collector, **kw):
        calls.append(org.org_id)
        return [_asset(f"a.{org.org_id}.com"), _asset(f"git.{org.org_id}.com")], []

    monkeypatch.setattr(cli, "collect_org", fake_collect)
    monkeypatch.setattr(
        cli, "check_exposure", lambda *a, **k: ([], [])
    )
    return calls


def test_collect_checkpoints_after_each_org(tmp_path, no_network, monkeypatch, capsys):
    """A stall mid-run must not lose the orgs that already finished."""
    snapshots: list[int] = []
    real_write = cli.write_jsonl_atomic

    def recording_write(rows, path):
        real_write(rows, path)
        snapshots.append(len(read_jsonl(path)))  # what survives a crash right now

    monkeypatch.setattr(cli, "write_jsonl_atomic", recording_write)
    code = cli.main([
        "collect", "-i", _config(tmp_path, ORG_B), "--all-enabled",
        "-o", str(tmp_path / "out"), "-q",
    ])
    capsys.readouterr()
    assert code == 0
    # Written once per org, complete each time — not buffered to the end.
    assert snapshots == [2, 4]
    out = next((tmp_path / "out").glob("*/*_collect.jsonl"))
    assert len(out.read_text().strip().splitlines()) == 4


def test_checkpoint_never_leaves_a_partial_file(tmp_path, no_network, monkeypatch,
                                                capsys):
    """The second org explodes; the first org's result must still be readable."""
    def exploding_collect(http, org, collector, **kw):
        if org.org_id == "y":
            raise OSError("index stalled")
        return [_asset("a.x.com"), _asset("git.x.com")], []

    monkeypatch.setattr(cli, "collect_org", exploding_collect)
    code = cli.main([
        "collect", "-i", _config(tmp_path, ORG_B), "--all-enabled",
        "-o", str(tmp_path / "out"), "-q",
    ])
    capsys.readouterr()
    assert code == 2
    out = next((tmp_path / "out").glob("*/*_collect.jsonl"))
    assert len(read_jsonl(out)) == 2  # complete and parseable, not truncated
    assert not list((tmp_path / "out").glob("*/*.tmp"))


def test_repeated_runs_do_not_duplicate_the_same_asset(
    tmp_path, no_network, capsys
):
    args = ["collect", "-i", _config(tmp_path), "--all-enabled",
            "-o", str(tmp_path / "out"), "-q"]
    cli.main(args)
    cli.main(args)  # same assets again: accumulate must dedup, not double up
    capsys.readouterr()
    out = next((tmp_path / "out").glob("*/*_collect.jsonl"))
    assert len(out.read_text().strip().splitlines()) == 2


def test_collect_accumulates_by_default(tmp_path, no_network, monkeypatch, capsys):
    """Flaky indexes return a different subset every run, so runs must add up
    without the operator remembering a flag."""
    config = _config(tmp_path)
    out = str(tmp_path / "out")
    cli.main(["collect", "-i", config, "--all-enabled", "-o", out, "-q"])

    # A second run where the indexes happen to return a different host.
    monkeypatch.setattr(
        cli, "collect_org",
        lambda http, org, collector, **kw: ([_asset("new.x.com")], []),
    )
    cli.main(["collect", "-i", config, "--all-enabled", "-o", out, "-q"])
    capsys.readouterr()
    path = next((tmp_path / "out").glob("*/*_collect.jsonl"))
    hosts = {json.loads(line)["host"] for line in path.read_text().splitlines()}
    assert hosts == {"a.x.com", "git.x.com", "new.x.com"}


def test_fresh_discards_the_previous_run(tmp_path, no_network, monkeypatch, capsys):
    config = _config(tmp_path)
    out = str(tmp_path / "out")
    cli.main(["collect", "-i", config, "--all-enabled", "-o", out, "-q"])
    monkeypatch.setattr(
        cli, "collect_org",
        lambda http, org, collector, **kw: ([_asset("new.x.com")], []),
    )
    cli.main(["collect", "-i", config, "--all-enabled", "-o", out, "-q", "--fresh"])
    capsys.readouterr()
    path = next((tmp_path / "out").glob("*/*_collect.jsonl"))
    hosts = {json.loads(line)["host"] for line in path.read_text().splitlines()}
    assert hosts == {"new.x.com"}


def test_run_probe_uses_the_same_stage_as_probe(tmp_path, no_network, monkeypatch):
    """Regression: `run --probe` used to skip body inspection entirely."""
    seen: dict = {}

    def fake_run_inspection(http, assets, prior=None, **kw):
        seen.update(kw)
        seen["assets"] = len(assets)
        from exposure_lens.probe.inspect import InspectionResult
        return InspectionResult()

    monkeypatch.setattr(cli, "run_inspection", fake_run_inspection)
    code = cli.main([
        "run", "-i", _config(tmp_path), "--all-enabled",
        "-o", str(tmp_path / "out"), "-q", "--probe", "--no-services",
    ])
    assert code == 0
    # The pipeline hands the full asset list to the same entry point the
    # `probe` command uses, with the live source.
    assert seen["assets"] == 2
    assert seen["source"] == "fetch"


def test_scan_writes_summary_without_liveness_bullets(
    tmp_path, no_network, capsys
):
    config = _config(tmp_path)
    out = str(tmp_path / "out")
    cli.main(["collect", "-i", config, "--all-enabled", "-o", out, "-q"])
    cli.main(["scan", "-i", config, "-o", out, "-q", "--no-services",
              "--min-severity", "low"])
    capsys.readouterr()
    summary = next((tmp_path / "out").glob("*/*_scan_summary.md")).read_text()
    assert "- [liveness]" not in summary
    assert "sensitive-host" in summary  # git.x.com was flagged


def test_validate_reports_enabled_count(tmp_path, capsys):
    cli.main(["validate", "-i", _config(tmp_path)])
    assert "1 enabled" in capsys.readouterr().out



# ---- resume ------------------------------------------------------------------

def test_network_down_stops_and_resume_continues(tmp_path, no_network, monkeypatch,
                                                 capsys):
    from exposure_lens.core.net import NetworkDown

    def down_on_y(http, org, collector, **kw):
        no_network.append(org.org_id)
        if org.org_id == "y":
            raise NetworkDown("3 requests in a row failed to connect")
        return [_asset(f"a.{org.org_id}.com", org=org.org_id)], []

    monkeypatch.setattr(cli, "collect_org", down_on_y)
    config = _config(tmp_path, ORG_B)
    out = tmp_path / "out"
    code = cli.main(["collect", "-i", config, "--all-enabled", "-o", str(out), "-q"])
    assert code == cli.EXIT_NETWORK_DOWN
    assert list(out.glob("*/*_collect.progress.json"))  # resumable

    # Link is back: --resume collects only the org that broke off.
    no_network.clear()
    monkeypatch.setattr(
        cli, "collect_org",
        lambda http, org, collector, **kw: (
            no_network.append(org.org_id)
            or ([_asset(f"a.{org.org_id}.com", org=org.org_id)], [])
        ),
    )
    code = cli.main(
        ["collect", "-i", config, "--all-enabled", "-o", str(out), "-q", "--resume"]
    )
    capsys.readouterr()
    assert code == 0
    assert no_network == ["y"]
    files = list(out.glob("*/*_collect.jsonl"))
    assert len(files) == 1  # same run continued, not a second file
    assert {r["host"] for r in read_jsonl(files[0])} == {"a.x.com", "a.y.com"}
    assert not list(out.glob("*/*.progress.json"))  # finished: nothing to resume


def test_resume_with_nothing_to_resume_is_an_error(tmp_path, no_network, capsys):
    code = cli.main([
        "collect", "-i", _config(tmp_path), "--all-enabled",
        "-o", str(tmp_path / "out"), "-q", "--resume",
    ])
    assert code == 2
    assert "--resume 없이" in capsys.readouterr().err


def test_scan_resume_only_asks_shodan_for_the_rest(tmp_path, no_network, monkeypatch,
                                                   capsys):
    from exposure_lens.core.net import NetworkDown
    from exposure_lens.scan import services

    config = _config(tmp_path)
    out = tmp_path / "out"
    rows = [
        {**_asset("a.x.com").to_dict(), "resolved_ip": "1.1.1.1"},
        {**_asset("b.x.com").to_dict(), "resolved_ip": "2.2.2.2"},
    ]
    (out / "20260101").mkdir(parents=True)
    assets_path = out / "20260101" / "000000_collect.jsonl"
    assets_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    asked = []

    def flaky(http, ip):
        asked.append(ip)
        if ip == "2.2.2.2":
            raise NetworkDown("down")
        return {"ports": [3306]}

    monkeypatch.setattr(cli, "check_exposure", services.check_exposure)
    monkeypatch.setattr(services.shodan, "internetdb", flaky)
    args = ["scan", "-i", config, "-o", str(out), "-q", "--min-severity", "low"]
    assert cli.main(args) == cli.EXIT_NETWORK_DOWN
    assert not list(out.glob("*/*_scan.jsonl"))  # an unfinished scan is not "done"

    asked.clear()
    monkeypatch.setattr(services.shodan, "internetdb", lambda http, ip: (
        asked.append(ip) or {"ports": [6379]}))
    assert cli.main([*args, "--resume"]) == 0
    capsys.readouterr()
    assert asked == ["2.2.2.2"]
    scan = read_jsonl(next(out.glob("*/*_scan.jsonl")))
    assert {f["rule"] for f in scan} >= {"port-3306", "port-6379"}
    assert not list(out.glob("*/*.progress.jsonl"))
