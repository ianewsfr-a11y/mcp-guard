"""v0.2: SARIF output and the new CLI options."""

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard import DEFAULT_RULESET, audit
from mcp_guard.cli import cli
from mcp_guard.sarif import locate, to_sarif

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "config_example.json"
FAKE_SERVER = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"


def _sarif(data, text="{}"):
    return to_sarif(audit(data), DEFAULT_RULESET, "mcp.json", text)


@pytest.mark.unit
def test_sarif_structure_and_severity():
    text = EXAMPLE.read_text(encoding="utf-8")
    report = _sarif(json.loads(text), text)
    run = report["runs"][0]
    assert report["version"] == "2.1.0"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["mcp-guard/command-execution"]["properties"]["security-severity"] == "9.5"
    assert rules["mcp-guard/network"]["defaultConfiguration"]["level"] == "warning"
    for result in run["results"]:
        assert result["ruleId"] in rules
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert result["partialFingerprints"]
    bash = next(r for r in run["results"] if "execute_bash_command" in r["message"]["text"])
    line = text.splitlines()[bash["locations"][0]["physicalLocation"]["region"]["startLine"] - 1]
    assert '"execute_bash_command"' in line


@pytest.mark.unit
def test_sarif_never_contains_secret_values():
    report = _sarif({"mcpServers": {"s": {"command": "node",
                                          "env": {"API_KEY": "sk-live-abcdef123456"}}}})
    assert "abcdef123456" not in json.dumps(report)


@pytest.mark.unit
def test_sarif_fingerprints_are_stable_and_distinct():
    data = {"tools": [{"name": "run_shell"}, {"name": "exec_cmd"}]}
    first, second = _sarif(data), _sarif(data)
    fps = [r["partialFingerprints"] for r in first["runs"][0]["results"]]
    assert fps == [r["partialFingerprints"] for r in second["runs"][0]["results"]]
    assert len({json.dumps(f) for f in fps}) == len(fps)


@pytest.mark.unit
@pytest.mark.parametrize("text,name,line", [
    ('{\n  "mcpServers": {\n    "fs": {}\n  }\n}', "fs", 3),
    ('{"tools": [\n {"name": "a"},\n {"name": "b"}\n]}', "b", 3),
    ("mcpServers:\n  - name: My Server\n    command: x\n", "My Server", 2),
    ("context_servers:\n  zed-srv:\n    command: x\n", "zed-srv", 2),
    ("{}", "missing", 1),
])
def test_locate(text, name, line):
    assert locate(text, name) == line


@pytest.mark.integration
def test_cli_sarif_to_file(tmp_path):
    out = tmp_path / "report.sarif"
    result = CliRunner().invoke(cli, ["inspect", str(EXAMPLE), "--format", "sarif",
                                      "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


@pytest.mark.integration
def test_cli_rules_option(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("ignore: [execute_bash_command, ops-toolbox]\n", encoding="utf-8")
    result = CliRunner().invoke(cli, ["inspect", str(EXAMPLE), "--rules", str(rules),
                                      "--format", "json", "--fail-on", "critical"])
    assert result.exit_code == 0, result.output
    names = {e["name"] for e in json.loads(result.output)}
    assert "execute_bash_command" not in names


@pytest.mark.integration
def test_cli_bad_rules_file_exits_2(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: [{category: x}]\n", encoding="utf-8")
    result = CliRunner().invoke(cli, ["inspect", str(EXAMPLE), "--rules", str(rules)])
    assert result.exit_code == 2


def _live_config(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"fake": {
        "command": sys.executable, "args": [str(FAKE_SERVER), "ok"]}}}), encoding="utf-8")
    return config


@pytest.mark.integration
def test_cli_live_requires_confirmation(tmp_path):
    result = CliRunner().invoke(cli, ["inspect", str(_live_config(tmp_path)), "--live"],
                                input="n\n")
    assert result.exit_code == 1  # click.Abort
    assert "run_shell" not in result.output


@pytest.mark.integration
def test_cli_live_with_yes(tmp_path):
    result = CliRunner().invoke(cli, ["inspect", str(_live_config(tmp_path)), "--live",
                                      "--yes", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output[result.output.index("["):])
    shell = next(e for e in payload if e["name"] == "run_shell")
    assert shell["server"] == "fake" and shell["risk"] == "CRITICAL"


@pytest.mark.integration
def test_cli_live_on_tools_only_file_is_a_no_op(tmp_path):
    tools = tmp_path / "tools.json"
    tools.write_text('{"tools": [{"name": "a"}]}', encoding="utf-8")
    result = CliRunner().invoke(cli, ["inspect", str(tools), "--live", "--yes"])
    assert result.exit_code == 0
    assert "no server to contact" in result.output


@pytest.mark.integration
def test_cli_table_shows_detected_format():
    result = CliRunner().invoke(cli, ["inspect", str(EXAMPLE)])
    assert "format: mcpServers" in result.output


@pytest.mark.integration
def test_python_dash_m_entry_point():
    import subprocess

    out = subprocess.run([sys.executable, "-m", "mcp_guard", "--version"],
                         capture_output=True, text=True, check=True)
    assert "0.2.0" in out.stdout
