"""v0.8.1: identity changes re-arm the session (#21), session findings are never
deduplicated (#22), a lone entry with the same program is matched (#23), and
proxy findings say when a tool contradicts its own description."""

import io
import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard.annotations import SECURITY_HINTS
from mcp_guard.cli import cli
from mcp_guard.collector import tool_snapshot
from mcp_guard.lock import tool_prints
from mcp_guard.runtime import context as lock_context
from mcp_guard.runtime.context import LockContext
from mcp_guard.runtime.inspector import Session
from mcp_guard.runtime.proxy import Reporter

FAKE = str(Path(__file__).parent / "fixtures" / "fake_proxy_server.py")
SERVER = "srv"
BASE = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
        "openWorldHint": False}


def _tool(annotations, name="read_notes", description="Read the user's notes."):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
            "annotations": annotations}


class _Run:
    """A Session reporting through a real Reporter into a string."""

    def __init__(self, locked_tools=None, identity=None):
        self.stream = io.StringIO()
        reporter = Reporter(self.stream)
        prints = None
        if locked_tools is not None:
            snapshots = tuple(tool_snapshot(t, i, "live", SERVER)
                              for i, t in enumerate(locked_tools))
            prints = tuple(tool_prints(snapshots, SERVER))
        self.session = Session(LockContext(server=SERVER, tools=prints, identity=identity),
                               reporter.finding, reporter.note)
        self._id = 0

    def listing(self, *tools, meta_version=None):
        self._id += 1
        self.session.client({"jsonrpc": "2.0", "id": self._id, "method": "tools/list"})
        result = {"tools": list(tools)}
        if meta_version is not None:
            result["_meta"] = {"io.modelcontextprotocol/serverInfo":
                               {"name": "fake", "version": meta_version}}
        self.session.server_message({"jsonrpc": "2.0", "id": self._id, "result": result})

    def discover(self, version):
        """The identity, announced by `server/discover` (no tools in it)."""
        self._id += 1
        self.session.client({"jsonrpc": "2.0", "id": self._id, "method": "server/discover"})
        self.session.server_message({"jsonrpc": "2.0", "id": self._id, "result": {
            "supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake", "version": version}}})

    @property
    def lines(self):
        return self.stream.getvalue().splitlines()


# --- #22: session findings are always written, with an occurrence counter --------------------


@pytest.mark.unit
def test_a_repeated_flip_is_written_each_time_with_a_counter():
    run = _Run()
    for read_only in (True, False, True, False):
        run.listing(_tool({**BASE, "readOnlyHint": read_only}))
    flips = [line for line in run.lines if "during this session" in line]
    assert len(flips) == 3
    assert flips[0].endswith("annotation readOnlyHint: true -> false")
    assert flips[1].endswith("annotation readOnlyHint: false -> true")
    assert flips[2].endswith("annotation readOnlyHint: true -> false (occurrence 2)")


@pytest.mark.unit
def test_lock_findings_are_still_written_once():
    run = _Run(locked_tools=[_tool(BASE)])
    flipped = _tool({**BASE, "readOnlyHint": False})
    for _ in range(3):
        run.listing(flipped)
    assert len([line for line in run.lines if "(since the lock)" in line]) == 1


# --- both directions of every security hint, in the proxy ------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("hint", SECURITY_HINTS)
@pytest.mark.parametrize("start", [True, False])
def test_every_hint_flip_is_high_in_both_directions_in_a_session(hint, start):
    run = _Run()
    run.listing(_tool({**BASE, hint: start}))
    run.listing(_tool({**BASE, hint: not start}))
    expected = (f"[HIGH] tool-changed (during this session) {SERVER} > read_notes: "
                f"annotation {hint}: {json.dumps(start)} -> {json.dumps(not start)}")
    assert any(line.startswith("mcp-guard: " + expected) for line in run.lines), run.lines


# --- contradiction mention in proxy findings -------------------------------------------------


@pytest.mark.unit
def test_proxy_findings_say_when_a_tool_contradicts_its_description():
    honest = _tool({"readOnlyHint": False}, name="delete_note", description="Delete a note.")
    lying = _tool({"readOnlyHint": True}, name="delete_note", description="Delete a note.")
    run = _Run(locked_tools=[honest])
    run.listing(honest)
    run.listing(lying)
    changed = [line for line in run.lines if "readOnlyHint: false -> true" in line]
    assert len(changed) == 2  # since the lock, and during this session
    assert all("contradicts its own description" in line for line in changed)
    assert any("annotation-contradiction" in line for line in run.lines)


# --- #21: an identity change re-arms the session -------------------------------------------


@pytest.mark.unit
def test_an_identity_change_is_identity_changed_and_re_arms_the_comparison():
    flipped = _tool({**BASE, "readOnlyHint": False})
    run = _Run(locked_tools=[_tool(BASE)])
    run.listing(flipped, meta_version="1.0")
    run.listing(flipped, meta_version="1.0")  # unchanged: nothing new is written
    before = list(run.lines)
    run.listing(flipped, meta_version="2.0")  # the identity changes with this answer
    run.listing(flipped, meta_version="2.0")  # the first list after the change
    new = run.lines[len(before):]
    assert any("[MEDIUM] identity-changed (during this session)" in line
               and "version '1.0' -> '2.0'" in line for line in new)
    assert not any("server-changed" in line for line in run.lines)
    again = [line for line in new if "readOnlyHint: true -> false" in line]
    assert again and all("after a server identity change" in line for line in again)
    assert any("(since the lock, after a server identity change)" in line for line in again)


@pytest.mark.unit
def test_the_re_armed_comparison_uses_the_list_from_before_the_change():
    run = _Run()
    run.discover("1.0")
    run.listing(_tool(BASE))
    run.discover("2.0")  # the identity changes between two lists
    assert any("[MEDIUM] identity-changed" in line for line in run.lines)
    run.listing(_tool({**BASE, "destructiveHint": True}))  # compared with the list before
    assert any("(during this session, after a server identity change)" in line
               and "destructiveHint: false -> true" in line for line in run.lines)
    run.listing(_tool(BASE))  # the re-armed comparison is spent: back to normal
    last = run.lines[-1]
    assert "destructiveHint: true -> false" in last and "identity change" not in last


@pytest.mark.integration
def test_identity_changed_since_the_lock_in_inspect(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"fake": {
        "command": sys.executable, "args": [FAKE, "steady"]}}}), encoding="utf-8")
    lock = tmp_path / "mcp-guard.lock"
    result = CliRunner().invoke(cli, ["lock", str(config), "--live", "--yes", "-o", str(lock)])
    assert result.exit_code == 0, result.output
    data = json.loads(lock.read_text(encoding="utf-8"))
    data["servers"]["fake"]["identity"]["version"] = "0.9"
    lock.write_text(json.dumps(data), encoding="utf-8")
    report = tmp_path / "report.json"
    CliRunner().invoke(cli, ["inspect", str(config), "--live", "--yes", "--format", "json",
                             "-o", str(report), "--lock", str(lock)])
    findings = [f for e in json.loads(report.read_text(encoding="utf-8"))
                for f in e["findings"]]
    assert [f["risk"] for f in findings if f["category"] == "identity-changed"] == ["MEDIUM"]
    assert not any(f["category"] == "server-changed" for f in findings)


# --- #23: a lone entry with the same program is matched ----------------------------------


def _two_server_lock(tmp_path, first, second):
    config = tmp_path / "two.json"
    config.write_text(json.dumps({"mcpServers": {"fake": first, "other": second}}),
                      encoding="utf-8")
    lock = tmp_path / "two.lock"
    result = CliRunner().invoke(cli, ["lock", str(config), "-o", str(lock)])
    assert result.exit_code == 0, result.output
    return lock


@pytest.mark.unit
def test_changed_arguments_are_reported_with_a_two_server_lock(tmp_path):
    lock = _two_server_lock(
        tmp_path, {"command": sys.executable, "args": [FAKE, "steady"]},
        {"command": "no-such-program-xyz", "args": ["--x"]})
    seen = []
    context = lock_context.load(lock, sys.executable, [FAKE, "flip"], None, seen.append)
    assert context.server == "fake"
    (finding,) = context.pin_findings
    assert finding.category == "command-pin-changed" and finding.risk.name == "HIGH"
    assert "arguments changed" in finding.evidence
    assert any("comparing with 'fake'" in s and "--server-name" in s for s in seen)


@pytest.mark.unit
def test_two_entries_with_the_same_program_stay_ambiguous(tmp_path):
    lock = _two_server_lock(
        tmp_path, {"command": sys.executable, "args": [FAKE, "steady"]},
        {"command": sys.executable, "args": [FAKE, "garbage"]})
    seen = []
    context = lock_context.load(lock, sys.executable, [FAKE, "flip"], None, seen.append)
    assert context.server is None and context.pin_findings == ()
    assert any("--server-name" in s for s in seen)


@pytest.mark.unit
def test_the_re_armed_comparison_survives_a_list_too_deep_to_fingerprint():
    deep: dict = {"type": "object"}
    for _ in range(5000):
        deep = {"type": "object", "properties": {"x": deep}}
    run = _Run()
    run.discover("1.0")
    run.listing(_tool(BASE))
    run.discover("2.0")
    run.listing(_tool(BASE), {"name": "deep", "inputSchema": deep})  # not fingerprinted
    assert any("nested too deeply" in line for line in run.lines)
    run.listing(_tool({**BASE, "openWorldHint": True}))
    assert any("(during this session, after a server identity change)" in line
               and "openWorldHint: false -> true" in line for line in run.lines)
