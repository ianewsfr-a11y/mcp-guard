"""v0.2: live tools/list discovery over stdio and Streamable HTTP."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from mcp_guard import Risk, audit
from mcp_guard.live import (
    HttpTransport,
    LiveError,
    StdioTransport,
    add_live_results,
    describe_launch,
    fetch_tools,
    launch_plan,
    list_tools,
)
from mcp_guard.models import ServerSpec
from mcp_guard.rules import DEFAULT_RULESET

FAKE_SERVER = str(Path(__file__).parent / "fixtures" / "fake_mcp_server.py")


def _stdio(mode):
    return ServerSpec(command=sys.executable, args=[FAKE_SERVER, mode])


# --- stdio -----------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["ok", "paginate", "noisy"])
def test_stdio_lists_all_tools(mode):
    tools = fetch_tools(_stdio(mode), timeout=10)
    assert [t["name"] for t in tools] == ["read_notes", "run_shell"]


@pytest.mark.integration
def test_stdio_server_without_tools_capability():
    assert fetch_tools(_stdio("no-tools"), timeout=10) == []


@pytest.mark.integration
def test_stdio_crash_is_reported():
    with pytest.raises(LiveError, match="exited"):
        fetch_tools(_stdio("crash"), timeout=10)


@pytest.mark.integration
def test_stdio_timeout_is_reported():
    with pytest.raises(LiveError, match="no answer"):
        fetch_tools(_stdio("hang"), timeout=1)


@pytest.mark.unit
def test_stdio_missing_executable():
    with pytest.raises(LiveError, match="cannot start"):
        StdioTransport("definitely-not-a-command-xyz", [], {}, timeout=1)


# --- Streamable HTTP --------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    deleted: ClassVar[list] = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = message.get("method")
        if method != "initialize" and self.headers.get("Mcp-Session-Id") != "s-123":
            self.send_response(400)
            self.end_headers()
            return
        if "id" not in message:
            self.send_response(202)
            self.end_headers()
            return
        if method == "initialize":
            body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "s-123")
            self.end_headers()
            self.wfile.write(body.encode())
            return
        assert self.headers.get("MCP-Protocol-Version") == "2025-06-18"
        assert self.headers.get("Authorization") == "Bearer t"
        notification = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress"})
        answer = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {
            "tools": [{"name": "send_email", "description": "Send an email."}]}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(f"data: {notification}\n\ndata: {answer}\n\n".encode())

    def do_DELETE(self):
        _Handler.deleted.append(self.headers.get("Mcp-Session-Id"))
        self.send_response(200)
        self.end_headers()


@pytest.fixture
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    server.shutdown()


@pytest.mark.integration
def test_http_session_sse_and_cleanup(http_server):
    spec = ServerSpec(url=http_server, headers={"Authorization": "Bearer t"})
    tools = fetch_tools(spec, timeout=5)
    assert [t["name"] for t in tools] == ["send_email"]
    assert _Handler.deleted[-1] == "s-123"


@pytest.mark.integration
def test_http_unreachable():
    with pytest.raises(LiveError, match="cannot reach"):
        fetch_tools(ServerSpec(url="http://127.0.0.1:9/mcp"), timeout=2)


@pytest.mark.unit
def test_http_rejects_non_http_schemes():
    with pytest.raises(LiveError, match="unsupported URL scheme"):
        HttpTransport("file:///etc/passwd", {}, timeout=1)


# --- Protocol & orchestration ----------------------------------------------


class _FakeTransport:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def request(self, method, params):
        self.calls.append((method, params))
        return self.answers.pop(0)

    def notify(self, method):
        self.calls.append((method, None))

    def close(self):
        pass


@pytest.mark.unit
def test_list_tools_rejects_malformed_page():
    transport = _FakeTransport([{"capabilities": {"tools": {}}}, {"oops": 1}])
    with pytest.raises(LiveError, match="no `tools` array"):
        list_tools(transport)


@pytest.mark.unit
def test_list_tools_sends_initialized_then_paginates():
    transport = _FakeTransport([
        {"capabilities": {"tools": {}}},
        {"tools": [{"name": "a"}], "nextCursor": "c1"},
        {"tools": [{"name": "b"}]},
    ])
    assert [t["name"] for t in list_tools(transport)] == ["a", "b"]
    assert [c[0] for c in transport.calls] == [
        "initialize", "notifications/initialized", "tools/list", "tools/list"]
    assert transport.calls[3][1] == {"cursor": "c1"}


@pytest.mark.unit
def test_launch_plan_skips_disabled_and_malformed():
    plan = launch_plan({"a": {"command": "node"}, "b": {"command": "x", "disabled": True},
                        "c": "not-a-dict"})
    assert [name for name, _ in plan] == ["a"]


@pytest.mark.unit
def test_describe_launch_never_shows_url_secrets():
    text = describe_launch(ServerSpec(url="https://u:p@h.example/mcp?token=abc"))
    assert text == "connect to https://h.example/mcp"


@pytest.mark.unit
def test_add_live_results_merges_tools_and_failures():
    servers = {"good": {"command": "node"}, "bad": {"command": "node"}}
    entries = audit({"mcpServers": servers})

    def fake_fetch(spec, timeout):
        if spec is plan[1][1]:
            raise LiveError("boom")
        return [{"name": "run_shell", "description": "exec"}]

    plan = launch_plan(servers)
    result = add_live_results(entries, plan, DEFAULT_RULESET, 5, fetch=fake_fetch)
    by_label = {e.label: e for e in result}
    assert by_label["good > run_shell"].risk == Risk.CRITICAL
    assert by_label["good > run_shell"].server == "good"
    assert by_label["bad"].findings[-1].category == "live-discovery-failed"
    assert by_label["bad"].risk == Risk.MEDIUM
