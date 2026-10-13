"""Textual is the optional `ui` extra: everything else works without it, and
`mcp-guard ui` says how to install it."""

import os
import subprocess  # nosec B404 - runs this repo's own code in a child interpreter
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard import ui
from mcp_guard.cli import cli

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "config_example.json"


@pytest.fixture
def no_textual(monkeypatch):
    """Make `import textual` fail, as if the extra were not installed."""
    for name in [n for n in sys.modules if n == "textual" or n.startswith("textual.")
                 or n == "mcp_guard.ui.app"]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "textual", None)  # None: ImportError on import


@pytest.mark.unit
def test_ensure_available_explains_how_to_install(no_textual):
    with pytest.raises(ui.UIUnavailable) as caught:
        ui.ensure_available()
    message = str(caught.value)
    assert "Textual" in message and "optional extra" in message
    assert "[ui]" in message and "pip install" in message


@pytest.mark.unit
def test_install_hint_uses_the_installed_distribution(monkeypatch):
    monkeypatch.setattr(ui, "_distribution", lambda: "some-dist")
    assert ui.install_hint().startswith('pip install "some-dist[ui]"')
    assert "pipx inject some-dist textual" in ui.install_hint()
    monkeypatch.setattr(ui, "_distribution", lambda: None)
    assert '".[ui]"' in ui.install_hint()  # source checkout: no name assumed


@pytest.mark.unit
def test_distribution_falls_back_to_package_files(monkeypatch):
    monkeypatch.setattr(ui, "entry_points", lambda **_: [])
    monkeypatch.setattr(ui, "packages_distributions", lambda: {"mcp_guard": ["from-files"]})
    assert ui._distribution() == "from-files"
    monkeypatch.setattr(ui, "packages_distributions", dict)
    assert ui._distribution() is None


@pytest.mark.integration
def test_ui_without_textual_fails_cleanly_before_any_work(no_textual, monkeypatch):
    def must_not_run(*_args, **_kwargs):
        raise AssertionError("servers must not be started when the UI cannot run")

    monkeypatch.setattr("mcp_guard.cli._live_results", must_not_run)
    result = CliRunner().invoke(cli, ["ui", str(EXAMPLE), "--live", "--yes"])
    assert result.exit_code != 0
    assert "needs Textual" in result.output and "[ui]" in result.output
    assert "Traceback" not in result.output


@pytest.mark.integration
def test_every_other_command_runs_without_textual(no_textual, tmp_path):
    runner = CliRunner()
    snap = tmp_path / "snap.json"
    lock = tmp_path / "mcp-guard.lock"
    commands = [
        ["--help"], ["--version"],
        ["inspect", str(EXAMPLE)], ["inspect", str(EXAMPLE), "--format", "json"],
        ["inspect", str(EXAMPLE), "--format", "sarif"], ["inspect", str(EXAMPLE), "--combined"],
        ["inspect", "--server", "npx -y @scope/pkg"],
        ["lock", str(EXAMPLE), "-o", str(lock)],
        ["inspect", str(EXAMPLE), "--lock", str(lock)],
        ["lock", str(EXAMPLE), "-o", str(lock), "--update"],
        ["snapshot", "save", str(EXAMPLE), "-o", str(snap)],
        ["snapshot", "diff", str(snap), str(snap), "--format", "json"],
        ["test-injection", str(ROOT / "examples" / "agents" / "naive_agent.py")],
    ]
    for args in commands:
        result = runner.invoke(cli, args)
        assert result.exit_code == 0, (args, result.output)
    assert "textual" not in sys.modules or sys.modules["textual"] is None


_BLOCKER = """
import sys
class Block:
    def find_spec(self, name, path=None, target=None):
        if name == "textual" or name.startswith("textual."):
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return None
sys.meta_path.insert(0, Block())
"""


@pytest.mark.integration
def test_a_python_without_textual_runs_inspect_and_explains_ui():
    """A child interpreter in which `textual` cannot be imported at all."""
    script = _BLOCKER + f"""
from click.testing import CliRunner
from mcp_guard.cli import cli
ok = CliRunner().invoke(cli, ["inspect", {str(EXAMPLE)!r}, "--format", "json"])
ui = CliRunner().invoke(cli, ["ui", {str(EXAMPLE)!r}])
print(ok.exit_code, len(__import__("json").loads(ok.output)), ui.exit_code)
print(ui.output)
assert "textual" not in sys.modules
"""
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          encoding="utf-8", cwd=ROOT, env=env, timeout=120,
                          check=False)  # nosec B603
    assert done.returncode == 0, done.stderr
    first, *rest = done.stdout.splitlines()
    exit_ok, entries, exit_ui = first.split()
    assert (exit_ok, exit_ui) == ("0", "1") and int(entries) > 0
    assert "needs Textual" in "\n".join(rest)


@pytest.mark.unit
def test_the_package_declares_textual_as_the_ui_extra():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    dependencies = text.split("dependencies = [", 1)[1].split("]", 1)[0]
    assert "textual" not in dependencies
    assert 'ui = ["textual>=1.0.0"]' in text
    assert "textual" not in (ROOT / "requirements.txt").read_text(encoding="utf-8")


@pytest.mark.unit
def test_run_ui_starts_the_app_when_textual_is_there(monkeypatch):
    pytest.importorskip("textual")
    from mcp_guard.ui import app

    started = []
    monkeypatch.setattr(app.AuditApp, "run", lambda self: started.append(self.run_data))
    ui.run_ui("a run", None)
    assert started == ["a run"]


class _Entry:
    def __init__(self, value, dist=None, with_dist=True):
        self.value = value
        if with_dist:
            self.dist = dist


class _Dist:
    def __init__(self, name):
        self.name = name


@pytest.mark.unit
def test_distribution_from_the_console_script(monkeypatch):
    entries = [_Entry("other.cli:main", _Dist("someone-else")),
               _Entry("mcp_guard.cli:cli", None),
               _Entry("mcp_guard.cli:cli", with_dist=False),
               _Entry("mcp_guard.cli:cli", _Dist("mcp-guard-audit"))]
    monkeypatch.setattr(ui, "entry_points", lambda **_: entries)
    assert ui._distribution() == "mcp-guard-audit"


@pytest.mark.unit
@pytest.mark.parametrize("error, expected", [
    (ModuleNotFoundError("No module named 'markdown_it'", name="markdown_it"),
     "installed but cannot load"),
    (AttributeError("broken"), "installed but cannot load (AttributeError: broken)"),
    (ModuleNotFoundError("No module named 'textual'", name="textual"), "optional extra"),
])
def test_missing_versus_broken_textual(monkeypatch, error, expected):
    def fail(name):
        raise error

    monkeypatch.setattr(ui.importlib, "import_module", fail)
    with pytest.raises(ui.UIUnavailable, match=expected.replace("(", r"\(").replace(")", r"\)")):
        ui.ensure_available()
