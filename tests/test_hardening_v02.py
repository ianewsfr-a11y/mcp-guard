"""v0.2 pre-release review: security and correctness regressions."""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard import DEFAULT_RULESET, ConfigFormatError, Risk, audit, discover, load_ruleset
from mcp_guard.analysis import redact_args
from mcp_guard.cli import cli
from mcp_guard.live import (
    LiveError,
    describe_launch,
    fetch_tools,
    launch_warnings,
    list_tools,
    resolve_executable,
)
from mcp_guard.live import stdio as stdio_module
from mcp_guard.live.protocol import MAX_TOOLS, result_of
from mcp_guard.models import ServerSpec
from mcp_guard.sarif import locate, to_sarif
from mcp_guard.text import printable

FAKE_SERVER = str(Path(__file__).parent / "fixtures" / "fake_mcp_server.py")


def _secrets(args):
    (entry,) = audit({"mcpServers": {"s": {"command": "node", "args": args}}})
    return [f.evidence for f in entry.findings if f.category == "hardcoded-secret"]


# --- Secrets in launch arguments -------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("args", [
    ["--api-key", "abcdef123456"],
    ["-e", "API_KEY=abcdef123456"],
    ["postgres://user:abcdef123456@db.local/app"],
    ["--token=abcdef123456"],
])
def test_secret_args_are_found_and_redacted(args):
    evidence = _secrets(args)
    assert evidence and all("abcdef123456" not in e for e in evidence)
    assert all("abcdef123456" not in a for a in redact_args(args))


@pytest.mark.unit
@pytest.mark.parametrize("args", [
    ["--token-file", "/run/secrets/token"],
    ["--key-path=/etc/key.pem"],
    ["--api-key", "${env:API_KEY}"],
    ["--token", "--verbose"],
])
def test_non_secret_args(args):
    assert _secrets(args) == []


@pytest.mark.unit
def test_describe_launch_redacts_and_lists_env():
    spec = ServerSpec(command=sys.executable,
                      args=["srv.py", "--api-key", "abcdef123456", "DB_PASSWORD=hunter22x"],
                      env={"NODE_OPTIONS": "--require ./x.js", "LOG": "1"})
    text = describe_launch(spec)
    assert "abcdef123456" not in text and "hunter22x" not in text
    assert "[env: LOG, NODE_OPTIONS]" in text
    assert os.path.basename(sys.executable) in text
    assert "NODE_OPTIONS" in launch_warnings(spec)[0]


# --- Executable resolution ---------------------------------------------------


@pytest.mark.unit
def test_refuses_binary_planted_in_cwd(tmp_path, monkeypatch):
    planted = tmp_path / "npx-planted.cmd"
    planted.write_text("", encoding="utf-8")
    monkeypatch.setattr("shutil.which", lambda _cmd: str(planted))
    with pytest.raises(LiveError, match="current directory"):
        resolve_executable("npx-planted", cwd=tmp_path)


@pytest.mark.unit
def test_bare_command_must_be_on_path():
    with pytest.raises(LiveError, match="not found on PATH"):
        resolve_executable("definitely-not-a-command-xyz")


@pytest.mark.unit
def test_explicit_path_is_used_as_written(tmp_path):
    assert resolve_executable(str(tmp_path / "srv")) == str(tmp_path / "srv")


# --- Control characters ------------------------------------------------------


@pytest.mark.unit
def test_printable_neutralizes_control_chars_and_truncates():
    assert printable("a\nb\x1b[2Kc") == "a?b?[2Kc"
    assert printable("x" * 10, 5) == "xxxx…"


@pytest.mark.integration
def test_table_does_not_echo_control_chars(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"tools": [{"name": "evil\n\x1b[2Kfake_row"}]}),
                    encoding="utf-8")
    result = CliRunner().invoke(cli, ["inspect", str(path)])
    assert result.exit_code == 0
    assert "\x1b[2K" not in result.output


# --- Live hardening ----------------------------------------------------------


@pytest.mark.unit
def test_server_error_message_is_truncated():
    with pytest.raises(LiveError) as info:
        result_of({"error": {"message": "x" * 10_000}}, "tools/list")
    assert len(str(info.value)) < 300


class _Endless:
    def __init__(self):
        self.calls = 0

    def request(self, method, params):
        self.calls += 1
        if method == "initialize":
            return {"capabilities": {"tools": {}}}
        return {"tools": [{"name": f"t{i}"} for i in range(1000)], "nextCursor": "more"}

    def notify(self, method):
        pass

    def close(self):
        pass


@pytest.mark.unit
def test_tool_count_is_capped():
    with pytest.raises(LiveError, match=str(MAX_TOOLS)):
        list_tools(_Endless())


@pytest.mark.integration
def test_stdio_output_cap(monkeypatch, tmp_path):
    script = tmp_path / "flood.py"
    script.write_text("import sys\nsys.stdin.readline()\n"
                      "sys.stdout.write('x' * 5000 + '\\n'); sys.stdout.flush()\n"
                      "import time; time.sleep(30)\n", encoding="utf-8")
    monkeypatch.setattr(stdio_module, "MAX_OUTPUT_BYTES", 1000)
    with pytest.raises(LiveError, match="exceeded"):
        fetch_tools(ServerSpec(command=sys.executable, args=[str(script)]), timeout=10)


class _Redirect(BaseHTTPRequestHandler):
    seen_auth: list = []  # noqa: RUF012

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:9/steal")
        self.end_headers()


@pytest.mark.integration
def test_http_redirects_are_not_followed():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
        with pytest.raises(LiveError, match="redirects are not followed"):
            fetch_tools(ServerSpec(url=url, headers={"Authorization": "Bearer t"}), timeout=5)
    finally:
        server.shutdown()


@pytest.mark.unit
def test_live_error_never_contains_url_secrets():
    with pytest.raises(LiveError) as info:
        fetch_tools(ServerSpec(url="http://u:pw-secret@127.0.0.1:9/mcp?token=tok-secret"),
                    timeout=2)
    assert "secret" not in str(info.value)


@pytest.mark.integration
def test_stdio_process_is_gone_after_close():
    spec = ServerSpec(command=sys.executable, args=[FAKE_SERVER, "ok"])
    from mcp_guard.live import open_transport

    transport = open_transport(spec, timeout=10)
    list_tools(transport)
    transport.close()
    assert transport._proc.poll() is not None


# --- Rules -------------------------------------------------------------------


def _ruleset(tmp_path, content):
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")
    return load_ruleset(path)


@pytest.mark.unit
def test_disable_applies_to_dedicated_checks(tmp_path):
    ruleset = _ruleset(tmp_path, "disable: [hardcoded-secret, privileged-access]\n")
    data = {"mcpServers": {"s": {"command": "docker", "args": ["run", "--privileged"],
                                 "env": {"API_KEY": "abcdef123456"}}}}
    (entry,) = audit(data, ruleset)
    assert entry.findings == ()


@pytest.mark.unit
@pytest.mark.parametrize("content,message", [
    ("disable: [netwrok]\n", "unknown categories"),
    ("rules:\n  - {category: a, risk: LOW, keywords: []}\n", "at least one keyword"),
    ("rules:\n  - {category: a, risk: LOW, keywords: [git-push]}\n", "single words"),
    (("rules:\n  - {category: a, risk: LOW, keywords: [x]}\n"
     "  - {category: a, risk: LOW, keywords: [y]}\n"), "duplicate"),
    ("rules:\n  - {category: hardcoded-secret, risk: LOW, keywords: [x]}\n", "reserved"),
])
def test_rules_validation(tmp_path, content, message):
    with pytest.raises(ConfigFormatError, match=message):
        _ruleset(tmp_path, content)


@pytest.mark.integration
def test_ignore_server_tool_label():
    from mcp_guard.live import add_live_results, launch_plan
    from mcp_guard.rules import RuleSet

    servers = {"srv": {"command": "node"}}
    ruleset = RuleSet(ignore=frozenset({"srv > run_shell"}))
    entries = add_live_results(audit({"mcpServers": servers}, ruleset), launch_plan(servers),
                               ruleset, 5, fetch=lambda s, t: [{"name": "run_shell"}])
    assert [e.label for e in entries] == ["srv"]


# --- Formats -----------------------------------------------------------------


@pytest.mark.unit
def test_all_server_locations_are_merged():
    data = {"mcpServers": {}, "servers": {"a": {"command": "x"}},
            "context_servers": {"a": {"command": "y"}}}
    found = discover(data)
    assert list(found.servers) == ["a", "a #2"]
    assert "servers (VS Code)" in found.format and "Zed" in found.format


@pytest.mark.unit
def test_zed_explicit_nulls_and_missing_path():
    data = {"context_servers": {
        "nulls": {"command": {"path": "sudo", "args": ["x"]}, "args": None},
        "nopath": {"command": {"args": ["x"]}},
    }}
    entries = {e.name: e for e in audit(data)}
    assert entries["nulls"].risk == Risk.CRITICAL
    assert entries["nopath"].findings[0].category == "malformed-entry"


# --- SARIF -------------------------------------------------------------------


@pytest.mark.unit
def test_sarif_same_category_findings_get_distinct_fingerprints():
    data = {"mcpServers": {"s": {"command": "node",
                                 "env": {"API_KEY": "aaaaaaaaaa", "TOKEN": "bbbbbbbbbb"}}}}
    results = to_sarif(audit(data), DEFAULT_RULESET, "m.json", "{}")["runs"][0]["results"]
    assert len({json.dumps(r["partialFingerprints"]) for r in results}) == 2


@pytest.mark.unit
def test_locate_duplicates_and_reserved_words():
    yaml_text = "mcpServers:\n  - name: R\n    command: a\n  - name: R\n    command: b\n"
    assert locate(yaml_text, "R #2") == 4
    json_text = '{"mcpServers": {\n "a": {"command": "x"},\n "command": {"command": "y"}\n}}'
    assert locate(json_text, "command") == 3
    assert locate('{\n"name": "a\\"b"\n}', 'a"b') == 2


@pytest.mark.integration
def test_sarif_outside_cwd_warns(tmp_path, monkeypatch):
    config = tmp_path / "mcp.json"
    config.write_text('{"tools": [{"name": "run_shell"}]}', encoding="utf-8")
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    result = CliRunner().invoke(cli, ["inspect", str(config), "--format", "sarif"])
    assert result.exit_code == 0
    assert "outside the current directory" in result.output
