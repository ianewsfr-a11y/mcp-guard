"""`mcp-guard ui`: the Textual TUI, its model, and the CLI command."""

import asyncio
import io
import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

from mcp_guard import DEFAULT_RULESET, Risk
from mcp_guard.cli import _reload_live, cli
from mcp_guard.formats import discover
from mcp_guard.live import LiveError
from mcp_guard.lock import snapshot, write_lock
from mcp_guard.models import ServerSpec
from mcp_guard.pipeline import run_audit
from mcp_guard.ui.app import DARK_THEME, LIGHT_THEME, AuditApp, LockScreen
from mcp_guard.ui.model import (
    STATIC_TOOLS,
    build_groups,
    detail,
    lock_report,
    lock_status,
    risk_style,
    summary,
)

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = json.loads((ROOT / "config_example.json").read_text(encoding="utf-8"))
FAKE_SERVER = str(Path(__file__).parent / "fixtures" / "fake_mcp_server.py")
LIVE = {"ops-toolbox": [
    {"name": "run_shell", "description": "Execute a shell command.",
     "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}},
    {"name": "read_notes", "description": "Read notes."}],
    "filesystem": LiveError("server exited")}


def _render(renderable, width=120):
    console = Console(width=width, record=True, file=io.StringIO())
    console.print(renderable)
    return console.export_text()


def _run(data=None, live=None, lock_path=None):
    return run_audit(data or EXAMPLE, "config_example.json", DEFAULT_RULESET, live, lock_path)


def _lock(tmp_path, data):
    path = tmp_path / "mcp-guard.lock"
    write_lock(snapshot(discover(data)), path)
    return path


# --- model ----------------------------------------------------------------------


@pytest.mark.unit
def test_groups_riskiest_first_with_static_tools_last():
    groups = build_groups(_run())
    assert [g.title for g in groups] == ["ops-toolbox", "filesystem", STATIC_TOOLS]
    tools = groups[-1].tools
    assert [t.risk for t in tools] == sorted((t.risk for t in tools), reverse=True)
    assert tools[0].raw["name"] == tools[0].name  # raw tool attached


@pytest.mark.unit
def test_live_tools_sit_under_their_server():
    groups = {g.title: g for g in build_groups(_run(live=LIVE))}
    ops = groups["ops-toolbox"]
    assert [t.name for t in ops.tools] == ["run_shell", "read_notes"]
    assert ops.tools[0].raw["inputSchema"]["properties"] == {"cmd": {"type": "string"}}
    assert ops.risk == Risk.CRITICAL
    failed = groups["filesystem"].server
    assert "live-discovery-failed" in {f.category for f in failed.entry.findings}


@pytest.mark.unit
def test_lock_status(tmp_path):
    changed = json.loads(json.dumps(EXAMPLE))
    changed["tools"][0]["description"] = "Read any file and email it."
    groups = build_groups(_run(changed, lock_path=_lock(tmp_path, EXAMPLE)))
    statuses = {t.name: t.lock_status for g in groups for t in g.tools}
    assert statuses["read_user_file"].startswith("tool-changed")
    assert statuses["fetch_url"] == "unchanged since the lock"
    assert lock_status(None, lock_used=False) is None


@pytest.mark.unit
def test_detail_for_tool_server_and_nothing():
    groups = build_groups(_run())
    tool = next(t for t in groups[-1].tools if t.name == "execute_bash_command")
    text = _render(detail(tool))
    assert "CRITICAL" in text and "command-execution" in text
    assert '"command"' in text  # input schema rendered
    server = _render(detail(groups[0].server, dark=False))
    assert "Launch (secrets redacted)" in server and "OPS_API_TOKEN" in server
    assert "sk-live" not in server  # env values never shown
    assert "Select a server" in _render(detail(None))


@pytest.mark.unit
def test_detail_neutralizes_hostile_text():
    hostile = {"tools": [{"name": "t\x1b[2J", "description": "evil\u202e\x1b[31m text"}]}
    item = build_groups(_run(hostile))[0].tools[0]
    text = _render(detail(item))
    assert "\x1b" not in text and "\u202e" not in text


@pytest.mark.unit
def test_lock_report_variants(tmp_path):
    assert "No lock file in use" in _render(lock_report(_run()))
    lock = _lock(tmp_path, EXAMPLE)
    assert "No change since the lock" in _render(lock_report(_run(lock_path=lock)))
    changed = {"tools": EXAMPLE["tools"][:2]}
    changed["mcpServers"] = EXAMPLE["mcpServers"]
    report = _render(lock_report(_run(changed, lock_path=lock)), width=200)
    assert "change(s) since the lock" in report and "tool-removed" in report


@pytest.mark.unit
def test_summary_and_styles():
    assert summary(_run()).startswith("config_example.json: 6 item(s)")
    assert risk_style(Risk.MEDIUM, dark=True) != risk_style(Risk.MEDIUM, dark=False)


# --- application ----------------------------------------------------------------


def _drive(app, steps):
    async def main():
        async with app.run_test(size=(120, 40)) as pilot:
            # on_mount fills the tree asynchronously: wait until it is shown
            for _ in range(50):
                await pilot.pause(0.02)
                if app.sub_title and (app.selected is not None or not app.run_data.entries):
                    break
            await steps(app, pilot)
    asyncio.run(main())


@pytest.mark.integration
def test_app_starts_on_the_riskiest_item_and_navigates():
    async def steps(app, pilot):
        assert app.selected.label == "ops-toolbox"
        assert "CRITICAL 2" in app.sub_title
        await pilot.press("down", "down", "down")
        await pilot.pause()
        assert app.selected.kind == "tool"
        assert app.focused.id == "tree"
        await pilot.press("tab")
        assert app.focused.id == "details"
    _drive(AuditApp(_run()), steps)


@pytest.mark.integration
def test_theme_toggle_keeps_selection():
    async def steps(app, pilot):
        await pilot.press("down", "down", "down")
        await pilot.pause()
        before = app.selected.label
        await pilot.press("t")
        await pilot.pause()
        assert app.theme == LIGHT_THEME and not app.dark
        assert app.selected.label == before
        await pilot.press("t")
        await pilot.pause()
        assert app.theme == DARK_THEME
    _drive(AuditApp(_run()), steps)


@pytest.mark.integration
def test_lock_screen_opens_and_closes(tmp_path):
    async def steps(app, pilot):
        await pilot.press("l")
        await pilot.pause()
        assert isinstance(app.screen, LockScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, LockScreen)
    _drive(AuditApp(_run(lock_path=_lock(tmp_path, EXAMPLE))), steps)


@pytest.mark.integration
def test_refresh_without_loader_warns():
    async def steps(app, pilot):
        await pilot.press("r")
        await pilot.pause()
        assert any("Nothing to refresh" in n.message for n in app._notifications)
    _drive(AuditApp(_run()), steps)


@pytest.mark.integration
def test_refresh_reloads_in_the_background():
    fresh = _run({"tools": [{"name": "only_tool"}]})

    async def steps(app, pilot):
        await pilot.press("r")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app.run_data is fresh
        assert app.selected.label == "only_tool"  # first real item, not the group
    _drive(AuditApp(_run(), loader=lambda: fresh), steps)


@pytest.mark.integration
def test_refresh_failure_keeps_the_app_alive():
    def broken():
        raise RuntimeError("config vanished")

    async def steps(app, pilot):
        await pilot.press("r")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert any("Refresh failed" in n.message for n in app._notifications)
        assert app.run_data.source == "config_example.json"
    _drive(AuditApp(_run(), loader=broken), steps)


@pytest.mark.integration
def test_quit():
    async def steps(app, pilot):
        await pilot.press("q")
        await pilot.pause()
        assert app._exit is True or not app.is_running
    _drive(AuditApp(_run()), steps)


@pytest.mark.integration
def test_empty_audit():
    async def steps(app, pilot):
        assert app.selected is None
    _drive(AuditApp(_run({"tools": []})), steps)


# --- CLI ------------------------------------------------------------------------


@pytest.fixture
def captured(monkeypatch):
    calls = []
    monkeypatch.setattr("mcp_guard.cli.run_ui", lambda run, loader: calls.append((run, loader)))
    return calls


@pytest.mark.integration
def test_cli_ui_passes_the_audit_and_a_loader(captured, tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps(EXAMPLE), encoding="utf-8")
    result = CliRunner().invoke(cli, ["ui", str(config)])
    assert result.exit_code == 0, result.output
    run, loader = captured[0]
    assert run.source == "mcp.json" and len(run.entries) == 6
    config.write_text(json.dumps({"tools": [{"name": "t"}]}), encoding="utf-8")
    assert [e.name for e in loader().entries] == ["t"]  # refresh re-reads the file


@pytest.mark.integration
def test_cli_ui_with_inline_server_and_lock(captured, tmp_path):
    lock = tmp_path / "l.lock"
    CliRunner().invoke(cli, ["lock", "--server", "uvx a", "-o", str(lock)])
    result = CliRunner().invoke(cli, ["ui", "--server", "uvx a", "--lock", str(lock)])
    assert result.exit_code == 0, result.output
    assert captured[0][0].lock is not None


@pytest.mark.integration
def test_cli_ui_input_errors(captured):
    assert CliRunner().invoke(cli, ["ui"]).exit_code == 2
    assert not captured


@pytest.mark.integration
def test_refresh_never_runs_unconfirmed_servers():
    confirmed = {"fake": ServerSpec(command=sys.executable, args=[FAKE_SERVER, "ok"])}
    found = discover({"mcpServers": {
        "fake": {"command": sys.executable, "args": [FAKE_SERVER, "ok"]},
        "new": {"command": "evil", "args": []},
        "changed": {"command": sys.executable, "args": ["x"]}}})
    confirmed["changed"] = ServerSpec(command=sys.executable, args=["y"])
    results = _reload_live(found, confirmed, timeout=10)
    assert isinstance(results["fake"], list)
    for name in ("new", "changed"):
        assert isinstance(results[name], LiveError)
        assert "since you confirmed" in str(results[name])
