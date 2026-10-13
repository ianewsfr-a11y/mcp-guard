import json
from pathlib import Path

import pytest
from click.testing import CliRunner

import mcp_guard
from mcp_guard import Risk, audit, cli, discover, strip_jsonc, tokenize

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "config_example.json"


def _by_name(entries):
    return {e.name: e for e in entries}


def _tool(name, description=""):
    return {"tools": [{"name": name, "description": description}]}


@pytest.mark.unit
def test_tokenize_splits_snake_camel_and_punctuation():
    assert tokenize("executeBashCommand", "read_user-file") == {
        "execute", "bash", "command", "read", "user", "file"}


@pytest.mark.unit
def test_tokenize_does_not_match_substrings():
    # "executive" must not be read as "exec"
    assert "exec" not in tokenize("executive summary")


@pytest.mark.unit
@pytest.mark.parametrize("name,description,expected", [
    ("read_user_file", "Read a file from documents.", Risk.LOW),
    ("fetch_url", "Download a page over HTTP.", Risk.MEDIUM),
    ("search_db", "Query the database.", Risk.MEDIUM),
    ("update_row", "Run an SQL UPDATE on a table.", Risk.HIGH),
    ("delete_file", "Remove a file.", Risk.HIGH),
    ("execute_bash_command", "Run a shell command.", Risk.CRITICAL),
    ("restart_service", "Restart a service as root.", Risk.CRITICAL),
])
def test_tool_risk_levels(name, description, expected):
    (entry,) = audit(_tool(name, description))
    assert entry.risk == expected


@pytest.mark.unit
def test_update_without_db_context_is_not_database_write():
    (entry,) = audit(_tool("update_profile_name", "Change display name."))
    assert "database-write" not in {f.category for f in entry.findings}


@pytest.mark.unit
def test_schema_property_names_are_analyzed():
    data = {"tools": [{"name": "run", "inputSchema": {
        "type": "object", "properties": {"shell": {"type": "string"}}}}]}
    (entry,) = audit(data)
    assert entry.risk == Risk.CRITICAL


@pytest.mark.unit
def test_hardcoded_secret_is_flagged_and_masked():
    data = {"mcpServers": {"s": {"command": "node", "args": ["srv.js"],
                                 "env": {"API_KEY": "sk-live-abcdef123456"}}}}
    (entry,) = audit(data)
    secret = next(f for f in entry.findings if f.category == "hardcoded-secret")
    assert secret.risk == Risk.HIGH
    assert "abcdef123456" not in secret.evidence


@pytest.mark.unit
@pytest.mark.parametrize("value", ["${API_KEY}", "$API_KEY", "%API_KEY%", ""])
def test_env_references_are_not_secrets(value):
    data = {"mcpServers": {"s": {"command": "node", "env": {"API_KEY": value}}}}
    (entry,) = audit(data)
    assert entry.findings == ()


@pytest.mark.unit
def test_broad_filesystem_scope_and_insecure_transport():
    data = {"mcpServers": {
        "fs": {"command": "npx", "args": ["server-filesystem", "/"]},
        "remote": {"url": "http://example.com/mcp"},
    }}
    entries = _by_name(audit(data))
    assert entries["fs"].risk == Risk.HIGH
    assert entries["remote"].risk == Risk.MEDIUM


@pytest.mark.unit
@pytest.mark.parametrize("data", [
    [{"name": "t"}],
    {"tools": [{"name": "t"}]},
    {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "t"}]}},
])
def test_tool_list_formats(data):
    _, tools = discover(data)
    assert [t["name"] for t in tools] == ["t"]


@pytest.mark.unit
@pytest.mark.parametrize("data", [
    {"mcpServers": {"a": {"command": "x"}}},
    {"servers": {"a": {"command": "x"}}},
    {"mcp": {"servers": {"a": {"command": "x"}}}},
])
def test_server_config_formats(data):
    servers, _ = discover(data)
    assert list(servers) == ["a"]


@pytest.mark.unit
@pytest.mark.parametrize("data", [{}, {"foo": 1}, "text", {"mcp": []}])
def test_invalid_formats_raise(data):
    with pytest.raises(mcp_guard.ConfigFormatError):
        discover(data)


@pytest.mark.integration
def test_example_config_end_to_end():
    entries = _by_name(audit(json.loads(EXAMPLE.read_text(encoding="utf-8"))))
    assert entries["read_user_file"].risk == Risk.LOW
    assert entries["filesystem"].risk == Risk.LOW
    assert entries["fetch_url"].risk == Risk.MEDIUM
    assert entries["update_customer_record"].risk == Risk.HIGH
    assert entries["execute_bash_command"].risk == Risk.CRITICAL
    assert entries["ops-toolbox"].risk == Risk.CRITICAL


@pytest.mark.integration
def test_cli_inspect_table_and_json():
    runner = CliRunner()
    table = runner.invoke(cli, ["inspect", str(EXAMPLE)])
    assert table.exit_code == 0, table.output
    assert "CRITICAL" in table.output

    as_json = runner.invoke(cli, ["inspect", str(EXAMPLE), "--json"])
    assert as_json.exit_code == 0
    assert json.loads(as_json.output)[0]["risk"] == "CRITICAL"


@pytest.mark.integration
@pytest.mark.parametrize("level,code", [("critical", 1), ("none", 0)])
def test_cli_fail_on(level, code):
    result = CliRunner().invoke(cli, ["inspect", str(EXAMPLE), "--fail-on", level])
    assert result.exit_code == code


@pytest.mark.integration
def test_cli_inspect_rejects_bad_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = CliRunner().invoke(cli, ["inspect", str(bad)])
    assert result.exit_code == 2
    assert "not valid JSON" in result.output


@pytest.mark.integration
def test_cli_test_injection(tmp_path):
    script = tmp_path / "server.py"
    script.write_text("print('server')", encoding="utf-8")
    result = CliRunner().invoke(cli, ["test-injection", str(script), "--json"])
    assert result.exit_code == 0
    payloads = json.loads(result.output)
    assert len(payloads) == 8
    assert len({p["id"] for p in payloads}) == 8


@pytest.mark.integration
def test_cli_test_injection_requires_existing_script():
    result = CliRunner().invoke(cli, ["test-injection", "does_not_exist.py"])
    assert result.exit_code == 2


# --- Hardening (pre-release review) ----------------------------------------


def _server(**spec):
    (entry,) = audit({"mcpServers": {"s": spec}})
    return entry


@pytest.mark.unit
@pytest.mark.parametrize("spec", [
    {"command": "docker", "args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"]},
    {"command": "cmd", "args": ["/c", "npx", "-y", "@modelcontextprotocol/server-memory"]},
    {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem",
                                "C:/Users/admin/Documents"]},
    {"command": r"C:\Program Files\nodejs\node.exe", "args": ["build/index.js"]},
])
def test_common_launch_lines_are_low(spec):
    assert _server(**spec).risk == Risk.LOW


@pytest.mark.unit
def test_shell_launcher_still_reports_what_it_runs():
    entry = _server(command="bash", args=["-c", "sudo node server.js"])
    assert {f.category for f in entry.findings} == {"privileged-access"}


@pytest.mark.unit
def test_docker_privileged_flag_is_critical():
    entry = _server(command="docker", args=["run", "--privileged", "img"])
    assert entry.risk == Risk.CRITICAL


@pytest.mark.integration
def test_rich_markup_in_names_does_not_crash(tmp_path):
    data = {"mcpServers": {"[/x]": {"command": "node"}},
            "tools": [{"name": "[bold]t[/bold]", "description": "[/]"}]}
    path = tmp_path / "[weird].json"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = CliRunner().invoke(cli, ["inspect", str(path)])
    assert result.exit_code == 0, result.output
    assert "[/x]" in result.output and "[bold]t[/bold]" in result.output


@pytest.mark.unit
@pytest.mark.parametrize("spec,leak", [
    ({"env": {"API_KEY": "sk-live-abcdef123456"}}, "sk-l"),
    ({"headers": {"Authorization": "Bearer abcdef123456"}}, "Bearer"),
    ({"args": ["--api-key=abcdef123456"]}, "abcd"),
    ({"url": "https://h.example/mcp?token=abcdef123456"}, "abcd"),
    ({"url": "https://user:abcdef123456@h.example/mcp"}, "abcd"),
])
def test_secrets_are_found_and_never_echoed(spec, leak):
    entry = _server(command="node", **spec)
    secrets = [f for f in entry.findings if f.category == "hardcoded-secret"]
    assert secrets
    assert all(leak not in f.evidence for f in entry.findings)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["${input:api-key}", "${env:API_KEY}",
                                   "Bearer ${input:token}"])
def test_vscode_variable_references_are_not_secrets(value):
    assert _server(command="node", headers={"Authorization": value}).findings == ()


@pytest.mark.unit
def test_insecure_url_is_reported_without_query():
    entry = _server(url="http://h.example/mcp?session=abc")
    (finding,) = entry.findings
    assert finding.evidence == "http://h.example/mcp"


@pytest.mark.unit
@pytest.mark.parametrize("url", ["http://localhost:3000/mcp", "http://127.0.0.1/mcp"])
def test_loopback_http_is_fine(url):
    assert _server(url=url).findings == ()


@pytest.mark.unit
@pytest.mark.parametrize("name", ["edit_file", "create_directory", "git_commit"])
def test_mutating_verbs_are_high(name):
    (entry,) = audit(_tool(name))
    assert entry.risk == Risk.HIGH


@pytest.mark.unit
def test_bad_entries_do_not_abort_the_audit():
    data = {"mcpServers": {"ok": {"command": "node", "env": None, "args": "x.js"},
                           "broken": "not-a-dict"},
            "tools": [{"name": "t", "description": None}, {"no_name": 1}, 42]}
    entries = _by_name(audit(data))
    assert entries["ok"].risk == Risk.LOW
    assert entries["t"].risk == Risk.LOW
    assert entries["broken"].findings[0].category == "malformed-entry"
    assert {"tools[1]", "tools[2]"} <= set(entries)


@pytest.mark.unit
def test_empty_server_map_is_valid():
    assert audit({"mcpServers": {}}) == ()


@pytest.mark.unit
def test_strip_jsonc_keeps_strings_intact():
    text = '{\n // c\n "u": "http://a/b", /* x */ "l": [1, 2,],\n}'
    assert json.loads(strip_jsonc(text)) == {"u": "http://a/b", "l": [1, 2]}


@pytest.mark.integration
@pytest.mark.parametrize("content,encoding", [
    ('{"mcpServers": {"a": {"command": "node"}}}', "utf-8-sig"),
    ('{"servers": {"a": {"command": "node"},}} // vscode', "utf-8"),
])
def test_cli_accepts_bom_and_jsonc(tmp_path, content, encoding):
    path = tmp_path / "mcp.json"
    path.write_text(content, encoding=encoding)
    assert CliRunner().invoke(cli, ["inspect", str(path)]).exit_code == 0


@pytest.mark.integration
def test_cli_rejects_non_utf8(tmp_path):
    path = tmp_path / "bin.json"
    path.write_bytes(b"\xff\xfe\x00\x81")
    result = CliRunner().invoke(cli, ["inspect", str(path)])
    assert result.exit_code == 2
