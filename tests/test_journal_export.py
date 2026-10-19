"""Issue #29, step 2: `mcp-guard journal export`, a proxy journal as OTLP/JSON traces."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

import mcp_guard.runtime.journal as journal_module
from mcp_guard import journal_cli
from mcp_guard.cli import cli
from mcp_guard.runtime.journal import Options, bounded_lines, read_journal
from mcp_guard.runtime.otlp import to_otlp

FAKE = str(Path(__file__).parent / "fixtures" / "fake_proxy_server.py")
TRACE_ID = "0af7651916cd43dd8448eb211c80319c"
PARENT = "00f067aa0ba902b7"
TRACE = f"00-{TRACE_ID}-{PARENT}-01"
C, S = "client->server", "server->client"


def _ts(second, ms=0):
    return f"2026-10-19T10:00:{second:02d}.{ms:03d}+00:00"


def _req(second, ident, method="tools/call", direction=C, **extra):
    return {"ts": _ts(second), "direction": direction, "method": method, "id": ident,
            "size": 80, "sha256": "a" * 64, **extra}


def _resp(second, ident, outcome="ok", direction=S, **extra):
    return {"ts": _ts(second, 500), "direction": direction, "method": None, "id": ident,
            "size": 40, "sha256": "b" * 64, "outcome": outcome, **extra}


def _end(second, server_exit=0):
    return {"ts": _ts(second), "event": "end", "dropped": 0, "server_exit": server_exit}


def _lines(*entries):
    return [json.dumps(e) if isinstance(e, dict) else e for e in entries]


def _spans(*entries):
    return read_journal(_lines(*entries)).spans


def _attrs(span):
    return dict(span.attributes)


# --- pairing --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_tool_call_and_its_response_make_one_span():
    (span,) = _spans(_req(1, 7, tool="get_weather", traceparent=TRACE),
                     _resp(2, 7, answers="tools/call"), _end(3))
    assert span.name == "tools/call get_weather"
    assert (span.trace_id, span.parent_id) == (TRACE_ID, PARENT)
    assert span.end_ns - span.start_ns == 1_500_000_000
    attrs = _attrs(span)
    assert attrs["mcp.method.name"] == "tools/call" and attrs["gen_ai.tool.name"] == "get_weather"
    assert attrs["gen_ai.operation.name"] == "execute_tool"
    assert attrs["jsonrpc.request.id"] == "7" and attrs["network.transport"] == "pipe"
    assert attrs["mcp_guard.trace.origin"] == "propagated" and attrs["mcp_guard.outcome"] == "ok"
    assert not span.error and "error.type" not in attrs


@pytest.mark.unit
def test_without_traceparent_each_request_is_a_local_root():
    first, second = _spans(_req(1, 1), _req(1, 2), _resp(2, 1), _resp(2, 2))
    assert first.parent_id is None and second.parent_id is None
    assert first.trace_id != second.trace_id and len(first.trace_id) == 32
    assert len(first.span_id) == 16 and first.span_id != second.span_id
    assert _attrs(first)["mcp_guard.trace.origin"] == "local"


@pytest.mark.unit
def test_the_export_is_deterministic():
    entries = (_req(1, 1), _resp(2, 1), _end(3))
    assert _spans(*entries) == _spans(*entries)


@pytest.mark.unit
@pytest.mark.parametrize("outcome, extra, error_type", [
    ("tool_error", {}, "tool_error"),
    ("error", {"error_code": -32602}, "-32602"),
    ("error", {}, "_OTHER"),
    ("unrecognized_result", {}, "unrecognized_result"),
    ("malformed", {}, "malformed")])
def test_a_failed_call_is_an_error_span(outcome, extra, error_type):
    (span,) = _spans(_req(1, 1), _resp(2, 1, outcome, **extra))
    attrs = _attrs(span)
    assert span.error and attrs["error.type"] == error_type
    expected = str(extra["error_code"]) if "error_code" in extra else None
    assert attrs.get("rpc.response.status_code") == expected


@pytest.mark.unit
def test_input_required_is_not_an_error():
    (span,) = _spans(_req(1, 1), _resp(2, 1, "input_required"))
    assert not span.error and _attrs(span)["mcp_guard.outcome"] == "input_required"


@pytest.mark.unit
def test_a_cancelled_request_ends_at_the_cancellation():
    cancel = {"ts": _ts(4), "direction": C, "method": "notifications/cancelled", "id": None,
              "size": 60, "sha256": "c" * 64, "cancels": 1}
    (span,) = _spans(_req(1, 1), cancel, _resp(9, 1), _end(10))
    assert span.error and _attrs(span)["error.type"] == "cancelled"
    assert span.end_ns - span.start_ns == 3_000_000_000


@pytest.mark.unit
@pytest.mark.parametrize("server_exit, error_type", [
    (1, "mcp_guard.transport_failure"), (0, "mcp_guard.no_response"),
    (None, "mcp_guard.no_response")])
def test_a_request_left_without_answer(server_exit, error_type):
    (span,) = _spans(_req(1, 1), _end(5, server_exit))
    assert span.error and _attrs(span)["error.type"] == error_type
    assert span.end_ns - span.start_ns == 4_000_000_000


@pytest.mark.unit
def test_a_journal_cut_short_ends_its_requests_at_its_last_line():
    (span,) = _spans(_req(1, 1), _req(3, 2, method="ping"), _resp(4, 2))[:1]
    assert _attrs(span)["error.type"] == "mcp_guard.no_response"
    assert span.end_ns - span.start_ns == 3_500_000_000


@pytest.mark.unit
def test_a_server_request_is_answered_by_the_client():
    (span,) = _spans(_req(1, 3, method="sampling/createMessage", direction=S),
                     _resp(2, 3, direction=C))
    attrs = _attrs(span)
    assert span.name == "sampling/createMessage" and attrs["mcp_guard.direction"] == S


@pytest.mark.unit
def test_runs_appended_to_one_journal_do_not_mix():
    spans = _spans(_req(1, 1), _end(2), _req(3, 1), _resp(4, 1))
    assert [_attrs(s)["mcp_guard.run"] for s in spans] == [1, 2]
    assert [_attrs(s)["mcp_guard.outcome"] for s in spans] == ["no_response", "ok"]


@pytest.mark.unit
def test_a_prompt_request_is_named_after_the_prompt():
    (span,) = _spans(_req(1, 1, method="prompts/get", prompt="review"), _resp(2, 1))
    assert span.name == "prompts/get review" and _attrs(span)["gen_ai.prompt.name"] == "review"


# --- what is not trusted, not kept ---------------------------------------------------------


@pytest.mark.unit
def test_bodies_and_unknown_fields_are_never_exported():
    request = _req(1, 1, tool="t", body='{"arguments": {"token": "s3cret-value"}}',
                   tracestate="vendor=s3cret-value")
    export = read_journal(_lines(request, _resp(2, 1, body="s3cret-value")))
    assert "s3cret-value" not in json.dumps(to_otlp(export.spans))


@pytest.mark.unit
def test_fields_edited_in_the_journal_are_checked_again():
    request = _req(1, 1, tool="bad name\x1b[31m", traceparent="00-zz")
    (span,) = _spans(request)
    attrs = _attrs(span)
    assert "gen_ai.tool.name" not in attrs and span.name == "tools/call"
    assert attrs["mcp_guard.trace.origin"] == "local"
    assert _spans(_req(1, 10**40), _req(2, True)) == ()  # an id that cannot be paired


@pytest.mark.unit
def test_id_zero_is_paired_like_any_other():
    cancel = {"ts": _ts(2), "direction": C, "method": "notifications/cancelled", "id": None,
              "size": 1, "sha256": "c" * 64, "cancels": 0}
    assert [_attrs(s)["mcp_guard.outcome"] for s in _spans(_req(1, 0), _resp(1, 0))] == ["ok"]
    assert _attrs(_spans(_req(1, 0), cancel)[0])["mcp_guard.outcome"] == "cancelled"


@pytest.mark.unit
def test_lines_that_are_not_entries_are_counted_and_skipped():
    export = read_journal(_lines("not json", "[1, 2]", json.dumps({"ts": "yesterday"}),
                                 json.dumps({**_req(1, 1), "direction": "sideways"}),
                                 _resp(2, 99), _req(3, 2), ""))
    assert len(export.spans) == 1
    assert export.skipped == 4 and export.unmatched == 1


@pytest.mark.unit
@pytest.mark.parametrize("ts", [1760868000, "2026-10-19T10:00:00", "2026-13-45T99:00:00+00:00"])
def test_an_entry_without_a_valid_aware_time_is_skipped(ts):
    export = read_journal(_lines({**_req(1, 1), "ts": ts}))
    assert export.spans == () and export.skipped == 1


@pytest.mark.unit
def test_an_entry_with_neither_method_nor_id_closes_nothing():
    export = read_journal(_lines(_req(1, 1), {**_resp(2, 1), "id": None}))
    assert export.unmatched == 0
    assert _attrs(export.spans[0])["mcp_guard.outcome"] == "no_response"


@pytest.mark.unit
def test_a_response_after_a_cancellation_is_ignored():
    cancel = {"ts": _ts(2), "direction": C, "method": "notifications/cancelled", "id": None,
              "size": 1, "sha256": "c" * 64, "cancels": 1}
    export = read_journal(_lines(_req(1, 1), cancel, _resp(3, 1)))
    assert len(export.spans) == 1 and export.unmatched == 0  # a late answer is expected


# --- OTLP/JSON ------------------------------------------------------------------------


@pytest.mark.unit
def test_otlp_json_follows_the_protobuf_json_mapping():
    spans = _spans(_req(1, 7, tool="get_weather", traceparent=TRACE),
                   _resp(2, 7, "error", error_code=-32603))
    document = to_otlp(spans)
    (resource,) = document["resourceSpans"]
    assert {"key": "service.name", "value": {"stringValue": "mcp-guard proxy"}} in (
        resource["resource"]["attributes"])
    (scope,) = resource["scopeSpans"]
    assert scope["scope"]["name"] == "mcp-guard"
    (span,) = scope["spans"]
    assert span["traceId"] == TRACE_ID and span["parentSpanId"] == PARENT
    assert span["kind"] == 1  # SPAN_KIND_INTERNAL: the proxy observes, it is no endpoint
    assert span["status"] == {"code": 2}
    assert isinstance(span["startTimeUnixNano"], str) and span["startTimeUnixNano"].isdigit()
    values = {a["key"]: a["value"] for a in span["attributes"]}
    assert values["mcp.method.name"] == {"stringValue": "tools/call"}
    assert values["mcp_guard.run"] == {"intValue": "1"}
    assert values["error.type"] == {"stringValue": "-32603"}


@pytest.mark.unit
def test_a_local_root_has_no_parent_and_an_unset_status():
    (span,) = to_otlp(_spans(_req(1, 1), _resp(2, 1)))["resourceSpans"][0]["scopeSpans"][0][
        "spans"]
    assert "parentSpanId" not in span and span["status"] == {}


# --- command line ---------------------------------------------------------------------


@pytest.mark.unit
def test_the_command_writes_the_file_and_a_summary(tmp_path):
    journal = tmp_path / "session.jsonl"
    journal.write_text("\n".join(_lines(_req(1, 1, traceparent=TRACE), _resp(2, 1),
                                        _req(3, 2), "garbage", _end(4))) + "\n",
                       encoding="utf-8")
    out = tmp_path / "traces.json"
    result = CliRunner().invoke(cli, ["journal", "export", str(journal), "--otlp",
                                      "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "2 spans" in result.output and "1 from an incoming trace" in result.output
    assert "1 line skipped" in result.output
    spans = json.loads(out.read_text(encoding="utf-8"))["resourceSpans"][0]["scopeSpans"][0][
        "spans"]
    assert len(spans) == 2


@pytest.mark.unit
def test_the_command_prints_to_stdout_without_output(tmp_path):
    journal = tmp_path / "session.jsonl"
    journal.write_text(json.dumps(_req(1, 1)) + "\n", encoding="utf-8")
    result = CliRunner().invoke(cli, ["journal", "export", str(journal)])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["resourceSpans"][0]["scopeSpans"][0]["spans"]


@pytest.mark.unit
def test_an_unreadable_journal_is_an_input_error(tmp_path, monkeypatch):
    result = CliRunner().invoke(cli, ["journal", "export", str(tmp_path / "missing.jsonl")])
    assert result.exit_code == 2
    journal = tmp_path / "locked.jsonl"
    journal.write_text("", encoding="utf-8")

    def denied(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(Path, "open", denied)
    result = CliRunner().invoke(cli, ["journal", "export", str(journal)])
    assert result.exit_code == 2 and "cannot read" in result.output
    assert "Permission denied" in result.output


# --- end to end ---------------------------------------------------------------------


@pytest.mark.integration
def test_a_real_proxy_journal_exports_one_span_per_call(tmp_path):
    journal = tmp_path / "session.jsonl"
    calls = [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
              "params": {"name": name, "_meta": {"traceparent": TRACE}}}
             for i, name in enumerate(["read_notes", "fail", "boom", "ask"], start=1)]
    data = b"".join((json.dumps(m) + "\n").encode() for m in calls)
    subprocess.run([sys.executable, "-m", "mcp_guard", "proxy", "--record", str(journal),
                    "--", sys.executable, FAKE, "steady"], input=data, capture_output=True,
                   timeout=60, env=dict(os.environ), check=False)
    out = tmp_path / "traces.json"
    result = CliRunner().invoke(cli, ["journal", "export", str(journal), "-o", str(out)])
    assert result.exit_code == 0, result.output
    spans = json.loads(out.read_text(encoding="utf-8"))["resourceSpans"][0]["scopeSpans"][0][
        "spans"]
    assert [s["name"] for s in spans] == [
        "tools/call read_notes", "tools/call fail", "tools/call boom", "tools/call ask"]
    assert [s["status"] for s in spans] == [{}, {"code": 2}, {"code": 2}, {}]
    assert {s["traceId"] for s in spans} == {TRACE_ID}


# --- review fixes: hostile or edited journals -----------------------------------------


@pytest.mark.unit
def test_deeply_nested_json_is_skipped_not_a_crash():
    export = read_journal(["[" * 200_000 + "]" * 200_000, '{"a":' * 50_000,
                           json.dumps(_req(1, 1))])
    assert export.skipped == 2 and len(export.spans) == 1


@pytest.mark.unit
def test_a_line_too_long_is_skipped_without_being_read_whole(monkeypatch):
    text = "\n".join([json.dumps(_req(1, 1)), "x" * 50, "y" * 25, "z" * 5]) + "\n"
    lines = list(bounded_lines(io.StringIO(text), limit=24))
    assert lines[1:] == [None, None, "z" * 5 + "\n"]
    monkeypatch.setattr(journal_module, "MAX_LINE", 10)
    assert read_journal([json.dumps(_req(1, 1))]).skipped == 1


@pytest.mark.unit
@pytest.mark.parametrize("ts", ["0001-01-01T00:00:00+00:00", "1969-12-31T23:59:59+00:00"])
def test_a_time_before_1970_is_skipped(ts):
    assert read_journal(_lines({**_req(1, 1), "ts": ts})).skipped == 1


@pytest.mark.unit
def test_a_reused_id_closes_the_request_left_without_answer():
    first, second = _spans(_req(1, 1, tool="a"), _req(3, 1, tool="b"), _resp(4, 1))
    assert _attrs(first)["mcp_guard.outcome"] == "no_response"
    assert first.end_ns - first.start_ns == 2_000_000_000
    assert _attrs(second)["mcp_guard.outcome"] == "ok"


@pytest.mark.unit
def test_limits_are_counted(monkeypatch):
    monkeypatch.setattr(journal_module, "MAX_OPEN", 2)
    export = read_journal(_lines(_req(1, 1), _req(1, 2), _req(1, 3)))
    assert export.dropped == 1 and len(export.spans) == 2
    monkeypatch.setattr(journal_module, "MAX_OPEN", 100)
    monkeypatch.setattr(journal_module, "MAX_SPANS", 1)
    export = read_journal(_lines(_req(1, 1), _resp(2, 1), _req(3, 2), _resp(4, 2)))
    assert export.dropped == 1 and len(export.spans) == 1


@pytest.mark.unit
@pytest.mark.parametrize("forged", ["cancelled", "no_response", "transport_failure", "x", 3])
def test_an_outcome_the_proxy_never_writes_is_malformed(forged):
    (span,) = _spans(_req(1, 1), _resp(2, 1, forged))
    assert _attrs(span)["mcp_guard.outcome"] == "malformed"


@pytest.mark.unit
@pytest.mark.parametrize("server_exit, outcome", [
    (True, "no_response"), (-9, "transport_failure"), ("1", "no_response")])
def test_only_an_integer_exit_code_means_the_server_stopped(server_exit, outcome):
    (span,) = _spans(_req(1, 1), _end(2, server_exit))
    assert _attrs(span)["mcp_guard.outcome"] == outcome


@pytest.mark.unit
@pytest.mark.parametrize("method", ["tools/call ghp_secret token", "", "x" * 129,
                                    "m" + chr(0xE9) + "thode"])
def test_a_method_outside_the_charset_is_not_exported(method):
    export = read_journal(_lines(_req(1, 1, method=method)))
    (span,) = export.spans
    assert span.name == "_OTHER" and _attrs(span)["mcp.method.name"] == "_OTHER"
    assert "secret" not in json.dumps(to_otlp(export.spans))


@pytest.mark.unit
@pytest.mark.parametrize("ident, exported", [
    (7, "7"), ("req-1:a.b_c", "req-1:a.b_c"), ("token ghp_x", None), ("a/b", None)])
def test_a_string_id_is_exported_only_when_it_looks_like_one(ident, exported):
    (span,) = _spans(_req(1, ident))
    assert _attrs(span).get("jsonrpc.request.id") == exported


@pytest.mark.unit
def test_ids_depend_on_the_salt_not_on_the_message():
    one = read_journal(_lines(_req(1, 1)), Options(salt="a")).spans[0]
    same = read_journal(_lines({**_req(1, 1), "sha256": "f" * 64}), Options(salt="a")).spans[0]
    other = read_journal(_lines(_req(1, 1)), Options(salt="b")).spans[0]
    assert (one.trace_id, one.span_id) == (same.trace_id, same.span_id)
    assert one.trace_id != other.trace_id and one.span_id != other.span_id


@pytest.mark.unit
def test_local_traces_ignore_an_incoming_traceparent():
    (span,) = read_journal(_lines(_req(1, 1, traceparent=TRACE)),
                           Options(propagate=False)).spans
    assert span.parent_id is None and span.trace_id != TRACE_ID
    assert _attrs(span)["mcp_guard.trace.origin"] == "local"


@pytest.mark.unit
def test_a_server_request_can_carry_the_trace_context():
    (span,) = _spans(_req(1, 3, method="sampling/createMessage", direction=S,
                          traceparent=TRACE), _resp(2, 3, direction=C))
    assert span.trace_id == TRACE_ID and span.parent_id == PARENT


@pytest.mark.unit
def test_a_cancellation_from_the_wrong_side_cancels_nothing():
    cancel = {"ts": _ts(2), "direction": S, "method": "notifications/cancelled", "id": None,
              "size": 1, "sha256": "c" * 64, "cancels": 1}
    export = read_journal(_lines(_req(1, 1), cancel, _resp(3, 1)))
    assert export.unmatched == 1 and _attrs(export.spans[0])["mcp_guard.outcome"] == "ok"


@pytest.mark.unit
@pytest.mark.parametrize("code", [True, 10**12, "x"])
def test_an_invalid_error_code_is_other(code):
    (span,) = _spans(_req(1, 1), _resp(2, 1, "error", error_code=code))
    attrs = _attrs(span)
    assert attrs["error.type"] == "_OTHER" and "rpc.response.status_code" not in attrs


# --- review fixes: the output file ---------------------------------------------------


def _small_journal(tmp_path):
    journal = tmp_path / "session.jsonl"
    journal.write_text(json.dumps(_req(1, 1)) + "\n", encoding="utf-8")
    return journal


@pytest.mark.unit
def test_the_output_cannot_be_the_journal(tmp_path):
    journal = _small_journal(tmp_path)
    result = CliRunner().invoke(cli, ["journal", "export", str(journal), "-o", str(journal)])
    assert result.exit_code == 2 and "journal itself" in result.output
    assert journal.read_text(encoding="utf-8").startswith('{"ts"')


@pytest.mark.unit
def test_an_unwritable_output_is_an_error_not_a_traceback(tmp_path):
    out = tmp_path / "missing-dir" / "traces.json"
    result = CliRunner().invoke(cli, ["journal", "export", str(_small_journal(tmp_path)),
                                      "-o", str(out)])
    assert result.exit_code == 2 and "cannot write" in result.output


@pytest.mark.unit
def test_a_failed_write_leaves_no_temporary_file(tmp_path, monkeypatch):
    def broken(*_args):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(journal_cli.os, "replace", broken)
    out = tmp_path / "traces.json"
    result = CliRunner().invoke(cli, ["journal", "export", str(_small_journal(tmp_path)),
                                      "-o", str(out)])
    assert result.exit_code == 2 and "No space left" in result.output
    assert sorted(p.name for p in tmp_path.iterdir()) == ["session.jsonl"]


@pytest.mark.unit
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions and symlinks")
def test_the_output_is_private_and_a_symlink_is_replaced_not_followed(tmp_path):
    target = tmp_path / "elsewhere.txt"
    target.write_text("keep me", encoding="utf-8")
    out = tmp_path / "traces.json"
    out.symlink_to(target)
    result = CliRunner().invoke(cli, ["journal", "export", str(_small_journal(tmp_path)),
                                      "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert target.read_text(encoding="utf-8") == "keep me" and not out.is_symlink()
    assert out.stat().st_mode & 0o777 == 0o600


@pytest.mark.unit
def test_the_salt_option_makes_the_export_repeatable(tmp_path):
    journal = _small_journal(tmp_path)
    runs = [CliRunner().invoke(cli, ["journal", "export", str(journal), *salt]).stdout
            for salt in (["--id-salt", "s"], ["--id-salt", "s"], [], [])]
    assert runs[0] == runs[1] and runs[2] != runs[3]


@pytest.mark.unit
def test_the_summary_tells_requests_not_exported(tmp_path, monkeypatch):
    monkeypatch.setattr(journal_module, "MAX_OPEN", 1)
    journal = tmp_path / "session.jsonl"
    journal.write_text("\n".join(_lines(_req(1, 1), _req(1, 2))) + "\n", encoding="utf-8")
    result = CliRunner().invoke(cli, ["journal", "export", str(journal)])
    assert "1 request not exported" in result.output


@pytest.mark.unit
def test_an_output_path_that_cannot_be_resolved_is_not_the_journal(tmp_path, monkeypatch):
    def broken(*_args, **_kwargs):
        raise OSError("loop")
    monkeypatch.setattr(journal_cli.os.path, "samefile", broken)
    out = tmp_path / "traces.json"
    out.write_text("old", encoding="utf-8")
    assert journal_cli._same_file(_small_journal(tmp_path), out) is False


@pytest.mark.unit
def test_cancelled_requests_remembered_are_bounded(monkeypatch):
    monkeypatch.setattr(journal_module, "MAX_OPEN", 2)
    entries = []
    for i in range(4):
        entries += [_req(1, i), {"ts": _ts(2), "direction": C, "method": "notifications/cancelled",
                                 "id": None, "size": 1, "sha256": "c" * 64, "cancels": i}]
    export = read_journal(_lines(*entries, *[_resp(3, i) for i in range(4)]))
    assert len(export.spans) == 4 and export.unmatched == 2


@pytest.mark.unit
def test_a_lone_carriage_return_does_not_swallow_entries():
    text = "x" * 50 + "\r" + json.dumps(_req(1, 1)) + "\n" + json.dumps(_req(2, 2)) + "\n"
    with_newline = io.StringIO(text, newline="\n")
    assert len(read_journal(bounded_lines(with_newline, limit=200)).spans) == 1


@pytest.mark.unit
def test_entries_the_proxy_dropped_are_reported(tmp_path):
    journal = tmp_path / "session.jsonl"
    end = {**_end(3), "dropped": 5}
    journal.write_text("\n".join(_lines(_req(1, 1), end, {**_end(4), "dropped": True})) + "\n",
                       encoding="utf-8")
    result = CliRunner().invoke(cli, ["journal", "export", str(journal)])
    assert "could not record 5 messages" in result.output


@pytest.mark.unit
@pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX")
def test_a_journal_that_is_not_a_regular_file_is_refused(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    result = CliRunner().invoke(cli, ["journal", "export", str(fifo)])
    assert result.exit_code == 2 and "not a regular file" in result.output
