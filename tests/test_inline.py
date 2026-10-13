"""v0.4: servers given inline with --server (no config file needed)."""

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard.cli import cli
from mcp_guard.inline import servers_from_cli, split_command
from mcp_guard.models import ConfigFormatError

FAKE_SERVER = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"


def _quoted(path):
    return f'"{path}"'


@pytest.mark.unit
@pytest.mark.parametrize("value,name,command,args", [
    ("npx -y @modelcontextprotocol/server-memory", "server-memory", "npx",
     ["-y", "@modelcontextprotocol/server-memory"]),
    ("npx -y @scope/pkg@1.2.3 --flag", "pkg", "npx", ["-y", "@scope/pkg@1.2.3", "--flag"]),
    ("uvx mcp-server-fetch", "mcp-server-fetch", "uvx", ["mcp-server-fetch"]),
    ("python server.py --port 3", "server", "python", ["server.py", "--port", "3"]),
    ("docker", "docker", "docker", []),
])
def test_commands(value, name, command, args):
    (spec_name, spec), = servers_from_cli((value,))["mcpServers"].items()
    assert spec_name == name
    assert spec == {"command": command, "args": args}


@pytest.mark.unit
def test_urls_and_duplicate_names():
    servers = servers_from_cli(("https://mcp.example.com/mcp?k=1", "uvx a", "uvx a"))
    assert servers["mcpServers"]["mcp.example.com"] == {"url": "https://mcp.example.com/mcp?k=1"}
    assert list(servers["mcpServers"]) == ["mcp.example.com", "a", "a #2"]


@pytest.mark.unit
def test_quoted_paths_with_spaces():
    parts = split_command('"C:\\Program Files\\node\\node.exe" "D:\\my srv\\index.js"')
    if sys.platform == "win32":
        assert parts == ["C:\\Program Files\\node\\node.exe", "D:\\my srv\\index.js"]
    else:
        assert parts[1].endswith("index.js") and len(parts) == 2


@pytest.mark.unit
@pytest.mark.parametrize("value", ["", '"unbalanced'])
def test_bad_values(value):
    with pytest.raises(ConfigFormatError):
        servers_from_cli((value,))


@pytest.mark.integration
def test_cli_requires_exactly_one_input(tmp_path):
    config = tmp_path / "c.json"
    config.write_text('{"tools": []}', encoding="utf-8")
    neither = CliRunner().invoke(cli, ["inspect"])
    both = CliRunner().invoke(cli, ["inspect", str(config), "--server", "uvx x"])
    assert neither.exit_code == 2 and both.exit_code == 2
    assert "either CONFIG_FILE or one or more --server" in neither.output


@pytest.mark.integration
def test_cli_static_audit_of_inline_servers():
    result = CliRunner().invoke(cli, ["inspect", "--server", "sudo node srv.js",
                                      "--server", "https://h.example/mcp?token=abcdef123456",
                                      "--format", "json"])
    assert result.exit_code == 0, result.output
    entries = {e["name"]: e for e in json.loads(result.output)}
    assert entries["srv"]["risk"] == "CRITICAL"
    assert "abcdef123456" not in result.output


@pytest.mark.integration
def test_cli_live_one_liner_with_a_real_stdio_server():
    command = f"{_quoted(sys.executable)} {_quoted(FAKE_SERVER)} ok"
    result = CliRunner().invoke(cli, ["inspect", "--live", "--yes", "--server", command,
                                      "--format", "json"])
    assert result.exit_code == 0, result.output
    entries = json.loads(result.output[result.output.index("["):])
    shell = next(e for e in entries if e["name"] == "run_shell")
    assert shell["server"] == "fake_mcp_server" and shell["risk"] == "CRITICAL"


@pytest.mark.integration
def test_cli_table_names_the_source():
    result = CliRunner().invoke(cli, ["inspect", "--server", "uvx mcp-server-fetch"])
    assert "command line" in result.output and "format: --server" in result.output


@pytest.mark.integration
def test_cli_lock_and_check_with_inline_servers(tmp_path):
    lock = tmp_path / "mcp-guard.lock"
    runner = CliRunner()
    created = runner.invoke(cli, ["lock", "--server", "uvx a", "-o", str(lock)])
    assert created.exit_code == 0, created.output
    assert '--server "uvx a"' in created.output
    changed = runner.invoke(cli, ["inspect", "--server", "uvx b", "--lock", str(lock),
                                  "--format", "json"])
    categories = {f["category"] for e in json.loads(changed.output) for f in e["findings"]}
    assert {"server-added", "server-removed"} <= categories


@pytest.mark.integration
def test_cli_sarif_with_inline_servers():
    result = CliRunner().invoke(cli, ["inspect", "--server", "sudo x", "--format", "sarif"])
    report = json.loads(result.output)
    uri = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert uri["artifactLocation"]["uri"] == "command line"
