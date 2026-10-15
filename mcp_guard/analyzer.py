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
from .poisoning import Signal, escalated, signals
from .poisoning import finding as poisoning_finding
from .rules import DEFAULT_RULESET, RuleSet
from .snapshot import MCPSnapshot, ServerSnapshot, ToolSnapshot
from .surfaces import prompt_fields, resource_fields
from .text import printable

LIVE_FAILED = "live-discovery-failed"
RESOURCE, PROMPT, INSTRUCTIONS = ("resource-poisoning", "prompt-poisoning",
                                  "server-instruction-poisoning")


_NOT_EXFILTRATION = frozenset({"uri", "mimeType"})  # URLs or types by nature


def _element_findings(rule: str, server: str, element: str, label: str,
                      fields: tuple[list[tuple[str, str]], int],
                      known: frozenset[str]) -> list[Finding]:
    kept, skipped = fields
    found = []
    for field, text in kept:
        hits = signals(text, known, element, exfiltration=field not in _NOT_EXFILTRATION)
        if hits:
            found.append(poisoning_finding(rule, server, element, field, hits,
                                           where=f"{label} {field}"))
    if skipped:
        found.append(poisoning_finding(rule, server, element, "(unscanned fields)", [Signal(
            "invisible/unscanned", "invisible",
            f"{skipped} field(s) not scanned: too many or too long", "", "")],
            where=f"{label} (unscanned fields)"))
    return escalated(found)


def surface_findings(server: ServerSnapshot, known: frozenset[str] = frozenset(),
                     ) -> tuple[Finding, ...]:
    """Hidden instructions in the server's instructions, resources and prompts."""
    found: list[Finding] = []
    if server.instructions:
        hits = signals(server.instructions, known)
        if hits:
            found.append(poisoning_finding(INSTRUCTIONS, server.name, server.name,
                                           "instructions", hits))
    for resource in server.resources:
        found += _element_findings(RESOURCE, server.name, resource.uri,
                                   f"resource '{printable(resource.uri, 80)}'",
                                   resource_fields(resource), known)
    for prompt in server.prompts:
        found += _element_findings(PROMPT, server.name, prompt.name,
                                   f"prompt '{printable(prompt.name, 80)}'",
                                   prompt_fields(prompt), known)
    return tuple(found)


def server_entry(server: ServerSnapshot, ruleset: RuleSet = DEFAULT_RULESET,
                 known: frozenset[str] = frozenset()) -> AuditEntry:
    if server.spec is None:
        return malformed_entry("server", server.name, server.parse_error or "entry")
    entry = analyze_server(server.name, server.spec, ruleset)
    extra: tuple[Finding, ...] = ()
    if server.live_error is not None:
        extra += (Finding(category=LIVE_FAILED, risk=Risk.MEDIUM, evidence=server.live_error,
                          field="live"),)
    extra += surface_findings(server, known)
    if not extra:
        return entry
    return AuditEntry(kind="server", name=server.name,
                      findings=ruleset.keep(entry.findings + extra))


def tool_entry(tool: ToolSnapshot, ruleset: RuleSet = DEFAULT_RULESET,
               known: frozenset[str] = frozenset()) -> AuditEntry:
    if tool.parse_error is not None:
        return malformed_entry("tool", tool.name, tool.parse_error, tool.server)
    return analyze_tool(tool.spec(), ruleset, tool.server, known)


def known_names(snapshot: MCPSnapshot) -> frozenset[str]:
    """Tool names, to recognize instructions about calling another tool."""
    return frozenset(t.name for t in snapshot.all_tools())


def analyze(snapshot: MCPSnapshot, ruleset: RuleSet = DEFAULT_RULESET,
            ) -> tuple[AuditEntry, ...]:
    """Servers, then tools from the file, then live tools; riskiest first
    (the sort is stable, so equal risks keep that order)."""
    known = known_names(snapshot)
    entries = [server_entry(s, ruleset, known) for s in snapshot.servers]
    entries += [tool_entry(t, ruleset, known) for t in snapshot.all_tools()]
    return sort_entries(entries, ruleset)


def audit(data: Any, ruleset: RuleSet = DEFAULT_RULESET) -> tuple[AuditEntry, ...]:
    """Static audit of a loaded config: `analyze(collect(data))`."""
    return analyze(collect(data), ruleset)
