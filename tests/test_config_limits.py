"""Config: limits reach the code, and bad input fails with a message."""
from __future__ import annotations

import pytest

from exposure_lens.core.config import load_config


def _write(tmp_path, text):
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


BASE = """
[[orgs]]
org_id = "x"
name = "X"
"""


def test_defaults_split_index_and_body_caps():
    from exposure_lens.core.config import CollectorConfig

    c = CollectorConfig()
    assert c.max_body_bytes < c.max_response_bytes


def test_source_limits_are_configurable(tmp_path):
    app = load_config(_write(tmp_path, """
[collector]
wayback_max_pages = 10
urlscan_limit = 300
""" + BASE))
    assert app.collector.wayback_max_pages == 10
    assert app.collector.urlscan_limit == 300


def test_missing_required_key_reports_which_one(tmp_path):
    with pytest.raises(ValueError, match="org_id"):
        load_config(_write(tmp_path, '[[orgs]]\nname = "X"\n'))


def test_body_cap_above_response_cap_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="max_body_bytes"):
        load_config(_write(tmp_path, """
[collector]
max_response_bytes = 1000
max_body_bytes = 2000
""" + BASE))
