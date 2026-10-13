"""Analysis: MCPSnapshot -> audit entries with findings.

Pure: no I/O, no raw config, no display. The rules themselves live in
`analysis` (one server or one tool); this module applies them to every
item of a snapshot. Every Finding returned has a stable `id` (see
`models.finding_id`).
"""

from __future__ import annotations

from typing import Any

from .analysis import analyze_server, analyze_tool, malformed_entry, sort_entries
from .collector import collect
from .models import AuditEntry, Finding, Risk
from .rules import DEFAULT_RULESET, RuleSet
from .snapshot import MCPSnapshot, ServerSnapshot, ToolSnapshot

LIVE_FAILED = "live-discovery-failed"


def server_entry(server: ServerSnapshot, ruleset: RuleSet = DEFAULT_RULESET) -> AuditEntry:
    if server.spec is None:
        return malformed_entry("server", server.name, server.parse_error or "entry")
    entry = analyze_server(server.name, server.spec, ruleset)
    if server.live_error is None:
        return entry
    failed = Finding(category=LIVE_FAILED, risk=Risk.MEDIUM, evidence=server.live_error)
    return AuditEntry(kind="server", name=server.name,
                      findings=ruleset.keep(entry.findings + (failed,)))


def tool_entry(tool: ToolSnapshot, ruleset: RuleSet = DEFAULT_RULESET) -> AuditEntry:
    if tool.parse_error is not None:
        return malformed_entry("tool", tool.name, tool.parse_error, tool.server)
    return analyze_tool(tool.spec(), ruleset, tool.server)


def analyze(snapshot: MCPSnapshot, ruleset: RuleSet = DEFAULT_RULESET,
            ) -> tuple[AuditEntry, ...]:
    """Servers, then tools from the file, then live tools; riskiest first
    (the sort is stable, so equal risks keep that order)."""
    entries = [server_entry(s, ruleset) for s in snapshot.servers]
    entries += [tool_entry(t, ruleset) for t in snapshot.all_tools()]
    return sort_entries(entries, ruleset)


def audit(data: Any, ruleset: RuleSet = DEFAULT_RULESET) -> tuple[AuditEntry, ...]:
    """Static audit of a loaded config: `analyze(collect(data))`."""
    return analyze(collect(data), ruleset)
