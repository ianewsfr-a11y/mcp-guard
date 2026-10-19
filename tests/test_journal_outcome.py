"""Issue #29, step 2: the journal records what an OpenTelemetry export needs
(outcome, tool, trace context, cancellations), never the bodies."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import mcp_guard.runtime.outcome as outcome_module
import mcp_guard.runtime.recorder as recorder_module
from mcp_guard.runtime.outcome import CLIENT, SERVER, Pending, details
from mcp_guard.runtime.recorder import Recorder, entry

FAKE = str(Path(__file__).parent / "fixtures" / "fake_proxy_server.py")
TRACE = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"


def _call(name, request_id=5, meta=None):
    params = {"name": name, "arguments": {"token": "s3cret-value"}}
    if meta is not None:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}


# --- requests and notifications ------------------------------------------------------


@pytest.mark.unit
def test_a_tool_call_records_the_tool_and_its_trace_context():
    meta = {"traceparent": TRACE, "tracestate": "vendor=opaque", "baggage": "user=alice"}
    assert details(_call("get_weather", meta=meta), CLIENT) == {
        "tool": "get_weather", "traceparent": TRACE}


@pytest.mark.unit
def test_a_prompt_request_records_the_prompt_name():
    message = {"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {"name": "review"}}
    assert details(message, CLIENT) == {"prompt": "review"}


@pytest.mark.unit
@pytest.mark.parametrize("name", ["ghp_" + "a" * 36 + " leaked", "a/b", "n" * 129, "",
                                  "café", "x\n", 3, None])
def test_a_name_outside_the_mcp_charset_is_flagged_not_copied(name):
    assert details(_call(name), CLIENT) == {"tool_invalid": True}


@pytest.mark.unit
def test_a_tool_call_sent_by_the_server_records_no_tool():
    assert details(_call("get_weather", meta={"traceparent": TRACE}), SERVER) == {
        "traceparent": TRACE}


@pytest.mark.unit
@pytest.mark.parametrize("value", [
    "00-0AF7651916CD43DD8448EB211C80319C-00f067aa0ba902b7-01",  # upper case
    "00-00000000000000000000000000000000-00f067aa0ba902b7-01",  # zero trace id
    "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",  # zero parent id
    "ff-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01",  # forbidden version
    TRACE + "-extra",                                           # version 00 is exact
    TRACE + "\n",
    "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7",     # flags missing
    "01-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01x",  # later version, glued
    "\x1b[31m", "", 42, None, ["x"]])
def test_an_invalid_traceparent_is_flagged_not_copied(value):
    assert details(_call("t", meta={"traceparent": value}), CLIENT) == {
        "tool": "t", "traceparent_invalid": True}


@pytest.mark.unit
def test_a_later_traceparent_version_keeps_its_known_fields_only():
    later = "01-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01-future"
    assert details(_call("t", meta={"traceparent": later}), CLIENT)["traceparent"] == later[:55]


@pytest.mark.unit
@pytest.mark.parametrize("direction", [CLIENT, SERVER])
def test_a_cancellation_records_the_request_it_cancels(direction):
    message = {"jsonrpc": "2.0", "method": "notifications/cancelled",
               "params": {"requestId": 5, "reason": "timeout after 30 s"}}
    assert details(message, direction) == {"cancels": 5}


@pytest.mark.unit
@pytest.mark.parametrize("request_id", [True, None, 1.5, {"a": 1}, "", 10**40])
def test_a_cancellation_of_an_invalid_id_records_nothing(request_id):
    message = {"method": "notifications/cancelled", "params": {"requestId": request_id}}
    assert details(message, CLIENT) == {}


@pytest.mark.unit
@pytest.mark.parametrize("params, expected", [
    (None, {}), ([], {}), ({"_meta": "x"}, {"tool_invalid": True}),
    ({"_meta": "x", "name": "t"}, {"tool": "t"}),
    ({"_meta": {"traceparent": TRACE}, "name": None},
     {"traceparent": TRACE, "tool_invalid": True})])
def test_malformed_params_never_raise(params, expected):
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
    assert details(message, CLIENT) == expected


@pytest.mark.unit
def test_peer_strings_are_capped():
    cancel = details({"method": "notifications/cancelled", "params": {"requestId": "i" * 500}},
                     CLIENT)
    assert len(cancel["cancels"]) == 128


# --- responses ----------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("message, expected", [
    ({"id": 5, "result": {"content": []}}, {"outcome": "ok"}),
    ({"id": 5, "result": {"resultType": "complete"}}, {"outcome": "ok"}),
    ({"id": 5, "result": {"content": [], "isError": True}}, {"outcome": "tool_error"}),
    ({"id": 5, "result": {"isError": "yes"}}, {"outcome": "ok"}),
    ({"id": 5, "result": {"resultType": "input_required"}}, {"outcome": "input_required"}),
    ({"id": 5, "result": {"resultType": "made-up"}}, {"outcome": "unrecognized_result"}),
    ({"id": 5, "result": {"resultType": 7}}, {"outcome": "unrecognized_result"}),
    ({"id": 5, "result": "not an object"}, {"outcome": "unrecognized_result"}),
    ({"id": 5, "error": {"code": -32602, "message": "Unknown tool: secret-name"}},
     {"outcome": "error", "error_code": -32602}),
    ({"id": 5, "error": {"code": "x", "message": "m"}}, {"outcome": "error"}),
    ({"id": 5, "error": {"code": True, "message": "m"}}, {"outcome": "error"}),
    ({"id": 5, "error": {"code": 10**40, "message": "m"}}, {"outcome": "error"}),
    ({"id": 5, "error": "oops"}, {"outcome": "error"}),
    ({"id": 5, "error": None, "result": {}}, {"outcome": "error"}),
    ({"id": 5, "result": {}, "_meta": {"traceparent": TRACE}}, {"outcome": "ok"}),
    ({"id": 5}, {"outcome": "malformed"}),
])
def test_a_response_records_its_outcome(message, expected):
    assert details({"jsonrpc": "2.0", **message}, SERVER) == expected


@pytest.mark.unit
@pytest.mark.parametrize("answers, expected", [
    ("tools/call", "tool_error"), (None, "tool_error"), ("resources/read", "ok")])
def test_is_error_is_a_tool_error_only_for_a_tool_call(answers, expected):
    message = {"jsonrpc": "2.0", "id": 5, "result": {"isError": True}}
    found = details(message, SERVER, answers)
    assert found["outcome"] == expected and found.get("answers") == answers


@pytest.mark.unit
@pytest.mark.parametrize("message", [None, [], "text", 3, {"method": "ping"},
                                     {"method": "notifications/initialized"},
                                     {"jsonrpc": "2.0"}, {"method": 7, "result": {}}])
def test_other_messages_add_nothing(message):
    assert details(message, CLIENT) == {}


# --- pairing a response with its request ------------------------------------------------


@pytest.mark.unit
def test_a_response_is_paired_with_the_request_of_the_other_side():
    pending = Pending()
    assert pending.answers(CLIENT, _call("t", 7)) is None
    assert pending.answers(SERVER, {"id": 7, "method": "sampling/createMessage"}) is None
    assert pending.answers(SERVER, {"id": 7, "result": {}}) == "tools/call"
    assert pending.answers(CLIENT, {"id": 7, "result": {}}) == "sampling/createMessage"
    assert pending.answers(SERVER, {"id": 7, "result": {}}) is None  # answered once
    assert pending.answers(SERVER, {"id": "7", "result": {}}) is None  # "7" is not 7
    assert pending.answers(CLIENT, "not a dict") is None


@pytest.mark.unit
def test_pending_requests_are_bounded(monkeypatch):
    monkeypatch.setattr(outcome_module, "_MAX_PENDING", 2)
    pending = Pending()
    for request_id in (1, 2, 3):
        pending.answers(CLIENT, {"id": request_id, "method": "ping"})
    assert pending.answers(SERVER, {"id": 1, "result": {}}) is None  # forgotten
    assert pending.answers(SERVER, {"id": 3, "result": {}}) == "ping"


# --- entries ------------------------------------------------------------------------


@pytest.mark.unit
def test_the_entry_keeps_no_argument_nor_error_message():
    line = json.dumps(_call("get_weather", meta={"traceparent": TRACE})).encode()
    data = entry(CLIENT, line, json.loads(line), bodies=False)
    assert data["tool"] == "get_weather" and data["traceparent"] == TRACE
    assert "s3cret-value" not in json.dumps(data)
    error = {"jsonrpc": "2.0", "id": 5, "error": {"code": -1, "message": "s3cret-value"}}
    data = entry(SERVER, json.dumps(error).encode(), error, bodies=False)
    assert data["error_code"] == -1 and "s3cret-value" not in json.dumps(data)


@pytest.mark.unit
def test_a_huge_integer_id_is_not_recorded():
    message = {"jsonrpc": "2.0", "id": 10**40, "method": "ping"}
    assert entry(CLIENT, b"{}", message, bodies=False)["id"] is None


@pytest.mark.unit
def test_a_batch_records_its_size():
    batch = [_call("a", 1), _call("b", 2)]
    data = entry(CLIENT, json.dumps(batch).encode(), batch, bodies=False)
    assert data["batch"] == 2 and "tool" not in data


@pytest.mark.unit
def test_details_failing_never_loses_the_entry(monkeypatch):
    def broken(*_args):
        raise RuntimeError("bug")
    monkeypatch.setattr(recorder_module, "details", broken)
    data = entry(CLIENT, b"{}", {"id": 1, "method": "x"}, bodies=False)
    assert data["method"] == "x" and data["note"] == "details not recorded (internal error)"


@pytest.mark.unit
def test_the_end_line_records_the_server_exit_code(tmp_path):
    path = tmp_path / "j.jsonl"
    recorder = Recorder.open(path, False, lambda _text: None)
    recorder.close(server_exit=3)
    end = json.loads(path.read_text(encoding="ascii").splitlines()[-1])
    assert end["event"] == "end" and end["server_exit"] == 3


# --- through the proxy ----------------------------------------------------------------


def _journal(tmp_path, *messages, command=(sys.executable, FAKE, "steady"), exit_code="0"):
    journal = tmp_path / "journal.jsonl"
    data = b"".join((json.dumps(m) + "\n").encode() for m in messages)
    subprocess.run([sys.executable, "-m", "mcp_guard", "proxy", "--record", str(journal),
                    "--", *command], input=data, capture_output=True,
                   timeout=60, env={**os.environ, "EXIT_CODE": exit_code}, check=False)
    return [json.loads(x) for x in journal.read_text(encoding="ascii").splitlines()]


@pytest.mark.integration
def test_the_proxy_journal_tells_the_outcome_of_each_call(tmp_path):
    entries = _journal(
        tmp_path, _call("read_notes", 1, {"traceparent": TRACE}), _call("fail", 2),
        _call("boom", 3), _call("ask", 4),
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}},
        exit_code="3")
    sent = {e["id"]: e for e in entries if e.get("direction") == CLIENT}
    got = {e["id"]: e for e in entries if e.get("direction") == SERVER}
    assert set(got) == {1, 2, 3, 4}, entries
    assert sent[1]["tool"] == "read_notes" and sent[1]["traceparent"] == TRACE
    assert [got[i]["outcome"] for i in (1, 2, 3, 4)] == [
        "ok", "tool_error", "error", "input_required"]
    assert all(got[i]["answers"] == "tools/call" for i in (1, 2, 3, 4))
    assert got[3]["error_code"] == -32603
    assert any(e.get("cancels") == 9 for e in entries)
    assert entries[-1]["event"] == "end" and entries[-1]["server_exit"] == 3
    assert "s3cret-value" not in json.dumps(entries)


@pytest.mark.integration
def test_a_server_that_does_not_start_has_no_exit_code(tmp_path):
    entries = _journal(tmp_path, command=("mcp-guard-no-such-command-29",))
    assert entries[-1]["event"] == "end" and entries[-1]["server_exit"] is None
