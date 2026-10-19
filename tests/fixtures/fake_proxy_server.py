"""Minimal stdio MCP server for the proxy tests. Usage: fake_proxy_server.py MODE

Modes:
  steady    the same tools on every tools/list
  flip      after the first tools/list, sends notifications/tools/list_changed
            (with a 2026-07-28 subscriptionId when SUBSCRIPTION=1), then
            serves read_notes with readOnlyHint false instead of true
  big       a tools/list answer of about 5 MB, written in several pieces
  garbage   a non-JSON line before every answer
  discover  answers server/discover (identity and capabilities, no
            initialize needed); DISCOVER_TOOLS=1 adds a non-standard tools array
  meta      every result carries _meta serverInfo, its version bumped after
            the first tools/list
  crlf      ends every line with CRLF (Windows style), to check no translation
In every mode, tools/call answers by tool name (see `call`).
Every mode writes "fake server stderr" on stderr at start. EXIT_CODE sets the
exit code used when stdin closes.
"""

import json
import os
import sys
import time

MODE = sys.argv[1] if len(sys.argv) > 1 else "steady"
state = {"lists": 0}


def tool(read_only=True, description="Read the user's notes."):
    return {"name": "read_notes", "description": description,
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
            "annotations": {"readOnlyHint": read_only, "destructiveHint": False}}


def send(message, pieces=1):
    data = (json.dumps(message) + ("\r\n" if MODE == "crlf" else "\n")).encode()
    if MODE == "garbage":
        sys.stdout.buffer.write(b"not json, a stray log line\n")
    size = max(1, len(data) // pieces)
    for start in range(0, len(data), size):
        sys.stdout.buffer.write(data[start:start + size])
        sys.stdout.buffer.flush()
        if pieces > 1:
            time.sleep(0.01)


def result(request_id, value):
    if MODE == "meta":
        version = "1.0" if state["lists"] <= 1 else "2.0"
        value = {**value, "_meta": {"io.modelcontextprotocol/serverInfo":
                                    {"name": "fake", "version": version}}}
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def tools_list(request_id):
    state["lists"] += 1
    if MODE == "big":
        send(result(request_id, {"tools": [tool(description="x" * 5_000_000)]}), pieces=40)
        return
    flipped = MODE == "flip" and state["lists"] > 1
    send(result(request_id, {"tools": [tool(read_only=not flipped),
                                       {"name": "list_notes", "description": "List notes."}]}))
    if MODE == "flip" and state["lists"] == 1:
        params = {}
        if os.environ.get("SUBSCRIPTION") == "1":
            params = {"_meta": {"io.modelcontextprotocol/subscriptionId": "sub-1"}}
        send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": params})


def call(request_id, name):
    """tools/call: `fail` reports a tool error, `boom` a JSON-RPC error, `ask`
    needs more input (2026-07-28), anything else succeeds."""
    if name == "boom":
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32603, "message": "internal error"}}
    value = {"content": [{"type": "text", "text": "done"}]}
    if name == "fail":
        value = {"content": [{"type": "text", "text": "failed"}], "isError": True}
    elif name == "ask":
        value = {"resultType": "input_required", "inputRequests": {}}
    return result(request_id, value)


def handle(message):
    method, request_id = message.get("method"), message.get("id")
    if request_id is None:
        return
    if method == "initialize":
        send(result(request_id, {"protocolVersion": "2025-06-18",
                                 "capabilities": {"tools": {"listChanged": True}},
                                 "serverInfo": {"name": "fake", "version": "1.0"}}))
    elif method == "server/discover":
        value = {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}},
                 "serverInfo": {"name": "fake", "version": "1.0"}, "resultType": "complete"}
        if os.environ.get("DISCOVER_TOOLS") == "1":
            value["tools"] = [tool()]
        send(result(request_id, value))
    elif method == "tools/list":
        tools_list(request_id)
    elif method == "tools/call":
        send(call(request_id, (message.get("params") or {}).get("name")))
    else:
        send(result(request_id, {}))


sys.stderr.write("fake server stderr\n")
sys.stderr.flush()
for line in sys.stdin.buffer:
    try:
        handle(json.loads(line))
    except json.JSONDecodeError:
        continue
sys.exit(int(os.environ.get("EXIT_CODE", "0")))
