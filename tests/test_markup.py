"""Untrusted text in Rich markup: a trailing backslash prints once."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from rich.markup import render

from mcp_guard.cli import cli
from mcp_guard.markup import escape

B = chr(92)  # a backslash
CONTEXTS = {"": "", " end": " end", "[/]": "", "[/b] z": " z", "[i]q[/i]": "q"}


@pytest.mark.parametrize("n", range(5))
@pytest.mark.parametrize("text", ["x{}", "{}[red]", "a{}[/x]", "{}", "[b]{}", "{}[b]{}"])
def test_escaped_text_renders_as_written(text, n):
    text = text.format(B * n, B * n)
    for after, shown in CONTEXTS.items():
        before = "[b]" if after in ("[/]", "[/b] z") else ""
        assert render(before + escape(text) + after).plain == text + shown


def _drive_root_config(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"fs": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:" + B]}}}),
        encoding="utf-8")
    return path


def test_inspect_shows_a_windows_drive_once(tmp_path):
    output = CliRunner().invoke(cli, ["inspect", str(_drive_root_config(tmp_path))]).output
    assert "broad-filesystem-scope" in output
    assert "C:" + B in output and "C:" + B * 2 not in output


def test_scan_shows_a_windows_drive_once(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    _drive_root_config(tmp_path).replace(home / ".cursor" / "mcp.json")
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.chdir(tmp_path)
    output = CliRunner().invoke(cli, ["scan"]).output
    assert "broad-filesystem-scope: C:" + B in output
    assert "C:" + B * 2 not in output
