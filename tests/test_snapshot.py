"""v0.6: versioned snapshot, collector -> analyzer separation, stable finding ids."""

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard import DEFAULT_RULESET, MCPSnapshot, analyze, audit, collect
from mcp_guard.analysis import audit_server, audit_tool, sort_entries, with_findings
from mcp_guard.cli import cli
from mcp_guard.collector import capture_live, launch_plan
from mcp_guard.formats import discover
from mcp_guard.live import (
    Capture,
    LiveError,
    capture_server,
    list_tools,
    merge_live_results,
)
from mcp_guard.lock import fingerprint, tool_print
from mcp_guard.models import Finding, Risk, ServerSpec, ToolSpec
from mcp_guard.renderer import entries_to_json
from mcp_guard.sarif import to_sarif

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = json.loads((ROOT / "config_example.json").read_text(encoding="utf-8"))
FAKE_SERVER = str(Path(__file__).parent / "fixtures" / "fake_mcp_server.py")
LIVE = {
    "ops-toolbox": [
        {"name": "run_shell", "description": "Execute a shell command.",
         "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
         "annotations": {"readOnlyHint": False}, "title": "Shell"},
        {"name": "read_notes", "description": "Read notes."},
        {"description": "no name"}],
    "filesystem": LiveError("server exited"),
}
SECRETS = ("sk-live-abc123", "hunter2", "pw-in-url", "q-token-xyz", "nested-secret")
WITH_SECRETS = {"mcpServers": {"remote": {
    "command": "node", "args": ["srv.js", "--api-key=sk-live-abc123"],
    "env": {"API_TOKEN": "hunter2", "REGION": "eu", "REF_KEY": "${env:MY_KEY}"},
    "headers": {"Authorization": "Bearer hunter2"},
    "url": "https://user:pw-in-url@h.example/mcp?token=q-token-xyz&v=2",
    "settings": {"client": {"api_key": "nested-secret", "mode": "fast"}}}}}
# one entry per leak found in the security review of the snapshot
LEAKY = {
    "windsurf": {"serverUrl": "https://h.example/mcp?api_key=SECRET-1", "url": ""},
    "token-user": {"url": "https://SECRET-2@h.example/mcp"},
    "empty-user": {"command": "x", "args": ["redis://:SECRET-3@cache:6379"]},
    "slash-pass": {"command": "x", "args": ["https://u:SEC/RET-4@h.example/p"]},
    "query-in-env": {"command": "x",
                     "env": {"DATABASE_URL": "postgres://h/db?password=SECRET-5"}},
    "subtree": {"command": "x", "auth": {"type": "bearer", "value": "SECRET-6"},
                "credentials": {"user": "a", "pass": "SECRET-7"}},
    "plural": {"command": "x",
               "settings": {"tokens": ["SECRET-8"], "api_keys": {"a": "SECRET-9"}}},
    "non-string": {"command": "x", "env": {"API_KEY": 1234567890},
                   "extra": {"secret": True}},
    "mixed-ref": {"command": "x", "headers": {"Authorization": "Bearer SECRET-10 ${X}"}},
    "bare-query": {"url": "https://h.example/mcp?SECRET-11"},
    "bad-url": {"command": "x", "args": ["http://[SECRET-12"]},
}


def _snap(data=None, live=None, at="2026-10-13T00:00:00+00:00"):
    return collect(data or EXAMPLE, "config_example.json", live, captured_at=at)


# --- canonical serialization ---------------------------------------------------


@pytest.mark.unit
def test_canonical_json_is_deterministic_and_ignores_capture_time():
    first = _snap(live=LIVE, at="2026-01-01T00:00:00+00:00")
    second = _snap(live=LIVE, at="2027-06-30T12:00:00+00:00")
    assert first.canonical_json() == second.canonical_json()
    assert first.digest == second.digest
    assert re.fullmatch(r"[0-9a-f]{64}", first.digest)
    assert first.to_json() != second.to_json()  # the full form keeps the timestamp


@pytest.mark.unit
def test_canonical_json_sorts_keys_and_is_compact():
    snap = _snap(live=LIVE)
    text = snap.canonical_json()
    assert "\n" not in text and ": " not in text
    assert text == json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))
    for volatile in ("captured_at", "generator", "config_example.json"):
        assert volatile not in text
    assert snap.digest == hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.mark.unit
def test_key_order_in_the_input_does_not_change_the_digest():
    tool = {"name": "t", "description": "d",
            "inputSchema": {"type": "object", "properties": {"a": {}, "b": {}}}}
    reordered = {"inputSchema": {"properties": {"b": {}, "a": {}}, "type": "object"},
                 "description": "d", "name": "t"}
    assert _snap({"tools": [tool]}).digest == _snap({"tools": [reordered]}).digest
    changed = {**tool, "description": "d2"}
    assert _snap({"tools": [tool]}).digest != _snap({"tools": [changed]}).digest


@pytest.mark.unit
def test_digest_ignores_the_source_path_and_survives_lone_surrogates():
    assert collect(EXAMPLE, "a.json").digest == collect(EXAMPLE, "/tmp/copy/b.json").digest
    snap = collect({"tools": [{"name": "t", "description": "bad " + chr(0xD800) + " text"}]})
    assert re.fullmatch(r"[0-9a-f]{64}", snap.digest)
    assert snap.to_json().isascii()


@pytest.mark.unit
def test_round_trip_through_json_keeps_the_content():
    snap = _snap(WITH_SECRETS, live={"remote": Capture(
        tools=({"name": "t", "annotations": {"destructiveHint": True}},),
        resources=({"uri": "file:///a", "name": "a"},),
        prompts=({"name": "p", "arguments": [{"name": "x"}]},))})
    again = MCPSnapshot.from_json(snap.to_json())
    assert again.canonical_json() == snap.canonical_json()
    assert again.captured_at == snap.captured_at


@pytest.mark.unit
def test_serialized_snapshot_never_contains_a_secret():
    snap = _snap(WITH_SECRETS)
    for text in (snap.canonical_json(), snap.to_json()):
        for secret in SECRETS:
            assert secret not in text
    spec = json.loads(snap.canonical_json())["servers"][0]["spec"]
    # env/header values are all redacted, except pure references
    assert spec["env"] == {"API_TOKEN": "<redacted>", "REGION": "<redacted>",
                           "REF_KEY": "${env:MY_KEY}"}
    assert spec["args"] == ["srv.js", "--api-key=<redacted>"]
    assert spec["url"].startswith("https://h.example/mcp?") and "v=2" in spec["url"]
    assert spec["settings"] == {"client": {"api_key": "<redacted>", "mode": "fast"}}
    # the in-memory snapshot keeps the values: the analyzer still sees them
    assert snap.servers[0].spec.env["API_TOKEN"] == "hunter2"
    assert "hardcoded-secret" in {f.category for f in analyze(snap)[0].findings}


@pytest.mark.unit
def test_storage_redaction_covers_the_security_review_cases():
    text = collect({"mcpServers": LEAKY}).canonical_json()
    assert [n for n in range(1, 13) if f"SECRET-{n}" in text] == []
    assert "RET-4" not in text and "1234567890" not in text
    servers = {s["name"]: s["spec"] for s in json.loads(text)["servers"]}
    assert servers["windsurf"]["serverUrl"].startswith("https://h.example/mcp?api_key=")
    assert servers["subtree"]["credentials"] == "<redacted>"
    assert servers["subtree"]["auth"] == "<redacted>"
    assert servers["plural"]["settings"]["tokens"] == "<redacted>"


# --- collection -----------------------------------------------------------------


@pytest.mark.unit
def test_snapshot_records_source_format_and_provenance():
    snap = _snap(live=LIVE)
    assert (snap.source, snap.mode, snap.schema_version) == ("config_example.json", "live", 1)
    assert "mcpServers" in snap.format and "tools list" in snap.format
    assert [t.provenance.path for t in snap.tools] == [f"tools[{i}]"
                                                       for i in range(len(snap.tools))]
    assert {t.provenance.origin for t in snap.tools} == {"config"}
    ops = snap.server("ops-toolbox")
    assert ops.live_status == "captured" and ops.provenance.path == "ops-toolbox"
    shell = ops.tools[0]
    assert (shell.provenance.origin, shell.provenance.path, shell.server) == (
        "live", "tools/list[0]", "ops-toolbox")
    assert shell.annotations == {"readOnlyHint": False}
    assert shell.metadata == {"title": "Shell"}
    assert shell.to_mcp() == LIVE["ops-toolbox"][0]
    assert ops.tools[2].parse_error == "name" and ops.tools[2].name == "tools[2]"
    failed = snap.server("filesystem")
    assert (failed.live_status, failed.live_error, failed.tools) == (
        "failed", "server exited", ())


@pytest.mark.unit
def test_malformed_entries_are_kept_with_their_error():
    snap = collect({"mcpServers": {"bad": {"args": {"not": "a list"}}},
                    "tools": [{"name": 3}, {"name": "ok"}]})
    assert snap.servers[0].spec is None and "args" in snap.servers[0].parse_error
    assert snap.tools[0].parse_error == "name" and snap.tools[0].name == "3"
    assert snap.tools[1].parse_error is None


@pytest.mark.unit
def test_non_dict_annotations_stay_as_sent():
    snap = collect({"tools": [{"name": "t", "annotations": None}]})
    assert snap.tools[0].annotations is None
    assert snap.tools[0].metadata == {"annotations": None}
    assert snap.tools[0].to_mcp() == {"name": "t", "description": "", "inputSchema": {},
                                      "annotations": None}


@pytest.mark.unit
def test_capture_with_resources_prompts_and_warnings():
    capture = Capture(tools=({"name": "t"},),
                      resources=({"uri": "file:///a.md", "name": "a", "mimeType": "text/md",
                                  "size": 3}, {"name": "no uri"}),
                      prompts=({"name": "p", "description": "d",
                                "arguments": [{"name": "x"}, "junk"]}, 7),
                      warnings=("prompts/list: boom",))
    server = collect({"mcpServers": {"s": {"command": "x"}}}, captures={"s": capture}).servers[0]
    assert [(r.uri, r.mime_type, r.metadata) for r in server.resources] == [
        ("file:///a.md", "text/md", {"size": 3})]
    assert [(p.name, p.arguments) for p in server.prompts] == [("p", ({"name": "x"},))]
    assert server.capture_warnings == ("prompts/list: boom",
                                       "resources/list[1]: no `uri`, not recorded",
                                       "prompts/list[1]: no `name`, not recorded")


@pytest.mark.unit
def test_capture_warnings_are_capped():
    capture = Capture(tools=(), resources=tuple({"bad": i} for i in range(100)))
    server = collect({"mcpServers": {"s": {"command": "x"}}}, captures={"s": capture}).servers[0]
    assert len(server.capture_warnings) == 21
    assert server.capture_warnings[-1] == "... and 80 more"


@pytest.mark.unit
def test_live_results_for_an_unknown_server_are_refused():
    with pytest.raises(ValueError, match="not in the config"):
        collect({"mcpServers": {"a": {"command": "x"}}}, captures={"ghost": []})


@pytest.mark.unit
def test_launch_plan_skips_disabled_and_malformed_servers():
    snap = collect({"mcpServers": {"on": {"command": "a"}, "off": {"command": "b",
                                                                    "disabled": True},
                                   "bad": {"command": {"no": "path"}}}})
    assert [name for name, _ in launch_plan(snap)] == ["on"]
    assert snap.server("off").disabled and not snap.server("on").disabled


class _Pages:
    """A transport whose tools/list keeps sending the same next cursor."""

    def __init__(self, cursor):
        self.cursor = cursor

    def request(self, method, params):
        if method == "initialize":
            return {"capabilities": {"tools": {}}}
        return {"tools": [{"name": "t"}], "nextCursor": self.cursor}

    def notify(self, method):
        pass

    def close(self):
        pass


@pytest.mark.unit
@pytest.mark.parametrize("cursor", [123, {"page": 2}, "x" * 5000])
def test_invalid_cursors_are_refused(cursor):
    with pytest.raises(LiveError, match="invalid nextCursor"):
        list_tools(_Pages(cursor))


@pytest.mark.unit
def test_a_repeated_cursor_stops_at_the_page_limit():
    from mcp_guard.live.protocol import MAX_PAGES
    assert len(list_tools(_Pages("same"))) == MAX_PAGES


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["full", "badlists"])
def test_live_capture_from_a_real_stdio_server(mode):
    spec = ServerSpec(command=sys.executable, args=[FAKE_SERVER, mode])
    results = capture_live([("fake", spec)], timeout=10)
    server = collect({"mcpServers": {"fake": spec.model_dump()}}, captures=results).servers[0]
    assert [t.name for t in server.tools] == ["read_notes", "run_shell"]
    if mode == "full":
        assert [r.uri for r in server.resources] == ["file:///notes/today.md"]
        assert [p.name for p in server.prompts] == ["summarize"]
        assert server.capture_warnings == ("resources/list[1]: no `uri`, not recorded",)
    else:  # lists fail: tools are kept, failures recorded
        assert server.resources == () and server.prompts == ()
        assert server.capture_warnings[0].startswith("resources/list: resources/list failed")
        assert "no `prompts` array" in server.capture_warnings[1]


@pytest.mark.integration
def test_capture_server_without_resources_capability():
    capture = capture_server(ServerSpec(command=sys.executable, args=[FAKE_SERVER, "ok"]), 10)
    assert len(capture.tools) == 2 and capture.resources == () and capture.prompts == ()


# --- analysis -------------------------------------------------------------------


def _legacy(data, live):
    """The pre-snapshot pipeline: raw config + raw live lists."""
    found = discover(data)
    entries = [audit_server(n, s) for n, s in found.servers.items()]
    entries += [audit_tool(i, t) for i, t in enumerate(found.tools)]
    return merge_live_results(sort_entries(entries, DEFAULT_RULESET), live, DEFAULT_RULESET)


def _shape(entries):
    return sorted((e.kind, e.label, e.risk, tuple(f.category for f in e.findings))
                  for e in entries)


@pytest.mark.unit
def test_analyzer_matches_the_legacy_pipeline():
    assert _shape(analyze(_snap(live=LIVE))) == _shape(_legacy(EXAMPLE, LIVE))
    assert _shape(audit(EXAMPLE)) == _shape(_legacy(EXAMPLE, {}))


@pytest.mark.unit
def test_findings_have_stable_unique_ids():
    first, second = analyze(_snap(live=LIVE)), analyze(_snap(live=LIVE))
    ids = [f.id for e in first for f in e.findings]
    assert ids and all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)
    assert len(set(ids)) == len(ids)
    assert ids == [f.id for e in second for f in e.findings]


@pytest.mark.unit
def test_findings_added_later_get_ids_too():
    entry = analyze(_snap())[0]
    extra = Finding(category="tool-changed", risk=Risk.HIGH, evidence="x")
    merged = with_findings((entry,), {(entry.kind, entry.label): (extra,)}, DEFAULT_RULESET)
    assert all(f.id for f in merged[0].findings)
    assert merged[0].findings[:-1] == entry.findings  # existing ids unchanged


@pytest.mark.unit
def test_finding_id_is_the_sarif_fingerprint_and_is_in_json():
    entries = analyze(_snap())
    results = to_sarif(entries, DEFAULT_RULESET, "config_example.json", "")["runs"][0]["results"]
    assert [r["partialFingerprints"]["mcpGuardFinding/v1"] for r in results] == [
        f.id for e in entries for f in e.findings]
    payload = json.loads(entries_to_json(entries))
    assert payload[0]["findings"][0]["id"] == entries[0].findings[0].id


@pytest.mark.unit
def test_lock_fingerprints_are_unchanged_by_the_snapshot():
    """Lock files written by v0.5 must still match: the tool metadata hash is
    computed over the same fields as before."""
    spec = ToolSpec.model_validate(LIVE["ops-toolbox"][0])
    others = {k: v for k, v in spec.model_dump().items()
              if k not in ("name", "description", "inputSchema")}
    legacy = hashlib.sha256(json.dumps(others, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False, default=str).encode()).hexdigest()
    tool = _snap(live=LIVE).server("ops-toolbox").tools[0]
    assert tool_print(tool, version=1).metadata == legacy  # how v1 locks are compared
    lock = fingerprint(_snap(live=LIVE))
    assert lock.mode == "live" and "ops-toolbox > read_notes" in {t.label for t in lock.tools}


# --- CLI ------------------------------------------------------------------------


@pytest.mark.integration
def test_inspect_json_reports_ids(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps(EXAMPLE), encoding="utf-8")
    result = CliRunner().invoke(cli, ["inspect", str(config), "--format", "json"])
    payload = json.loads(result.output)
    assert all(re.fullmatch(r"[0-9a-f]{32}", f["id"]) for e in payload for f in e["findings"])
