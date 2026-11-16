"""Issue #25: read-only tools on a server granted broad or privileged access.

A tool list declaring `readOnlyHint: true` is only a claim; the real boundary
is the access of the process behind it. When a live audit sees read-only tools
on a server whose launch line grants a root/home directory or privileged
flags, a server-level `read-only-undermined-by-access` finding (MEDIUM) names
the tools and the grant.
"""

import pytest

from mcp_guard.analyzer import READ_ONLY_SCOPE, analyze
from mcp_guard.collector import collect
from mcp_guard.models import Risk
from mcp_guard.rules import RuleSet

READ_ONLY = {"name": "read_notes", "description": "Read notes.",
             "annotations": {"readOnlyHint": True}}
LISTER = {"name": "list_files", "description": "List files.",
          "annotations": {"readOnlyHint": True}}
WRITER = {"name": "save_note", "description": "Save a note.",
          "annotations": {"readOnlyHint": False}}


def _analyze(args, tools, server="fs"):
    data = {"mcpServers": {server: {"command": "npx", "args": args}}}
    snap = collect(data, "mcp.json", {server: list(tools)})
    return analyze(snap)


def _server_finding(entries, server="fs"):
    for entry in entries:
        if entry.kind == "server" and entry.name == server:
            for finding in entry.findings:
                if finding.category == READ_ONLY_SCOPE:
                    return finding
    return None


@pytest.mark.unit
def test_broad_scope_with_read_only_tools_is_flagged():
    finding = _server_finding(_analyze(["-y", "fs-server", "~"], [READ_ONLY, LISTER]))
    assert finding is not None
    assert finding.risk is Risk.MEDIUM
    assert "list_files, read_notes" in finding.evidence  # sorted, read-only only
    assert "broad-filesystem-scope" in finding.evidence
    assert "readOnlyHint: true" in finding.evidence


@pytest.mark.unit
def test_privileged_access_with_read_only_tool_is_flagged():
    finding = _server_finding(_analyze(["--privileged", "img"], [READ_ONLY]))
    assert finding is not None
    assert "privileged-access" in finding.evidence
    assert "read_notes" in finding.evidence


@pytest.mark.unit
def test_names_only_the_read_only_tools():
    finding = _server_finding(_analyze(["-y", "fs-server", "~"], [READ_ONLY, WRITER]))
    assert finding is not None
    assert "read_notes" in finding.evidence
    assert "save_note" not in finding.evidence


@pytest.mark.unit
def test_narrow_scope_is_not_flagged():
    assert _server_finding(_analyze(["-y", "fs-server", "./data"], [READ_ONLY, LISTER])) is None


@pytest.mark.unit
def test_no_read_only_tool_is_not_flagged():
    assert _server_finding(_analyze(["-y", "fs-server", "~"], [WRITER])) is None


@pytest.mark.unit
def test_static_audit_without_live_tools_does_not_fire():
    data = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs-server", "~"]}}}
    assert _server_finding(analyze(collect(data, "mcp.json"))) is None


@pytest.mark.unit
def test_finding_can_be_suppressed():
    ruleset = RuleSet(disabled=frozenset({READ_ONLY_SCOPE}))
    data = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs-server", "~"]}}}
    snap = collect(data, "mcp.json", {"fs": [READ_ONLY, LISTER]})
    categories = {f.category for e in analyze(snap, ruleset) for f in e.findings}
    assert READ_ONLY_SCOPE not in categories
    assert "broad-filesystem-scope" in categories  # the grant itself still reported
