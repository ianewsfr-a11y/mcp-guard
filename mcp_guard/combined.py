"""Experimental config-level rule `agent-exfiltration-surface`.

Every other rule looks at one tool. This one looks at what an agent gets
from all the active servers of a config together: if some tool reads private
data, some tool brings in untrusted content and some tool can send data out,
an injected instruction can chain them into an exfiltration, even though
each tool looks fine alone.

Opt-in (`inspect --combined`). One finding per config at most:

- MEDIUM, or HIGH when a server providing `reads_private` also has
  `broad-filesystem-scope`; never CRITICAL;
- the evidence lists the tools behind each capability and names the least
  populated one as the cut point (the fewest tools to remove or gate);
- its id hashes the rule and the sorted names of the servers involved, so
  adding a tool to a server already involved keeps the same id.

Statuses: `triggered`; `clear` (all tools seen, a capability is missing);
`partial` (a capability is missing, but some servers or tools could not be
seen); `not-evaluated` (no tool list at all, e.g. static mode); `disabled`.
Only `triggered` is a finding: the others never change the exit code.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .capabilities import CAPABILITIES, Capability, TaggedTool, tag_tool
from .models import AuditEntry, Finding, Risk
from .rules import RuleSet
from .snapshot import MCPSnapshot, ToolSnapshot

RULE = "agent-exfiltration-surface"  # described in rules.EXPERIMENTAL_CHECKS
MAX_LISTED = 10  # tools named per capability in the evidence (all are in `surface`)
# when two capabilities have as few tools, cut the outbound channel first
_CUT_ORDER: tuple[Capability, ...] = ("sends_external", "ingests_untrusted", "reads_private")

Status = Literal["triggered", "clear", "partial", "not-evaluated", "disabled"]
Surface = dict[Capability, tuple[TaggedTool, ...]]  # capability -> tools carrying it


class CombinedResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: Status
    reason: str = ""
    surface: Surface = {}
    servers: tuple[str, ...] = ()  # involved servers, sorted
    file_tools: bool = False  # tools listed in the file itself are involved
    unevaluated: tuple[str, ...] = ()  # active servers without a tool list
    malformed: int = 0  # tools that could not be parsed, so could not be tagged
    suppressed: tuple[TaggedTool, ...] = ()  # tools whose tags a --rules override removed
    cut_point: Capability | None = None
    entry: AuditEntry | None = None
    source: str = "config"  # the config's name, as on the entry


def combined_id(servers: tuple[str, ...], file_tools: bool = False) -> str:
    """Rule + sorted involved servers (+ whether file tools are involved).
    Tool names are left out, so adding a tool to an involved server keeps it."""
    identity = json.dumps([f"mcp-guard/{RULE}", sorted(servers), file_tools])
    return hashlib.sha256(identity.encode()).hexdigest()[:32]


def _ignored(tool: ToolSnapshot, ruleset: RuleSet, server_names: set[str]) -> bool:
    """`ignore` as in the report, except that an ignored *server* name never
    hides a tool of that name on another server."""
    return tool.label in ruleset.ignore or (tool.name in ruleset.ignore
                                            and tool.name not in server_names)


def _in_scope(snapshot: MCPSnapshot, ruleset: RuleSet,
              ) -> tuple[list[ToolSnapshot] | None, list[str], int]:
    """Tools of the file and of every active, reached server (None when no
    tool list was read at all); the active servers whose tools are unknown;
    and how many servers are active. Ignored servers and tools are left out."""
    tools = list(snapshot.tools)
    read_any = bool(snapshot.tools)
    unevaluated, active = [], 0
    for server in snapshot.servers:
        if server.spec is None or server.disabled or server.name in ruleset.ignore:
            continue
        active += 1
        if server.live_status == "captured":
            tools += server.tools
            read_any = True
        else:
            unevaluated.append(server.name)
    if not read_any:
        return None, unevaluated, active
    names = {s.name for s in snapshot.servers}
    return [t for t in tools if not _ignored(t, ruleset, names)], unevaluated, active


def _not_evaluated(snapshot: MCPSnapshot, unevaluated: list[str], active: int) -> str:
    if snapshot.mode == "static":
        return "no tool list: run with --live"
    return "no server could be reached" if unevaluated else (
        "no active server" if not active else "no tool list")


def _risk(surface: Surface, entries: tuple[AuditEntry, ...]) -> Risk:
    broad = {e.name for e in entries if e.kind == "server"
             and any(f.category == "broad-filesystem-scope" for f in e.findings)}
    readers = {t.server for t in surface["reads_private"]}
    return Risk.HIGH if readers & broad else Risk.MEDIUM


def _names(tools: tuple[TaggedTool, ...] | list[str]) -> str:
    labels = [t if isinstance(t, str) else t.label for t in tools]
    more = len(labels) - MAX_LISTED
    return ", ".join(labels[:MAX_LISTED]) + (f" and {more} more" if more > 0 else "")


def _caveats(unevaluated: list[str], malformed: int) -> list[str]:
    caveats = []
    if unevaluated:
        caveats.append(f"not evaluated (no tool list): {_names(unevaluated)}")
    if malformed:
        caveats.append(f"{malformed} malformed tool(s) could not be tagged")
    return caveats


def _evidence(surface: Surface, cut: Capability, caveats: list[str]) -> str:
    parts = [f"{c}: {_names(surface[c])}" for c in CAPABILITIES]
    text = ("; ".join(parts) + f". Cut point: {cut} ({len(surface[cut])} tool(s): "
            f"{_names(surface[cut])}), remove them or require approval for each call")
    return text + "".join(f". {c[0].upper()}{c[1:]}" for c in caveats)


def evaluate(snapshot: MCPSnapshot, entries: tuple[AuditEntry, ...],
             ruleset: RuleSet) -> CombinedResult:
    result = _evaluate(snapshot, entries, ruleset)
    return result.model_copy(update={"source": snapshot.source or "config"})


def _evaluate(snapshot: MCPSnapshot, entries: tuple[AuditEntry, ...],
              ruleset: RuleSet) -> CombinedResult:
    if RULE in ruleset.disabled:
        return CombinedResult(status="disabled", reason="disabled in the rules file")
    tools, unevaluated, active = _in_scope(snapshot, ruleset)
    if tools is None:
        return CombinedResult(status="not-evaluated", unevaluated=tuple(unevaluated),
                              reason=_not_evaluated(snapshot, unevaluated, active))
    malformed = sum(t.parse_error is not None for t in tools)
    tagged = [tag_tool(t, ruleset.capabilities, ruleset.exceptions)
              for t in tools if t.parse_error is None]
    surface = {c: tuple(t for t in tagged if c in t.capabilities) for c in CAPABILITIES}
    involved = [t for ts in surface.values() for t in ts]
    servers = tuple(sorted({t.server for t in involved if t.server is not None}))
    file_tools = any(t.server is None for t in involved)
    caveats = _caveats(unevaluated, malformed)
    common = CombinedResult(status="clear", surface=surface, servers=servers,
                            file_tools=file_tools, unevaluated=tuple(unevaluated),
                            malformed=malformed,
                            suppressed=tuple(t for t in tagged if t.suppressed))
    missing = [c for c in CAPABILITIES if not surface[c]]
    if missing:
        return common.model_copy(update={
            "status": "partial" if caveats else "clear",
            "reason": "; ".join(["missing: " + ", ".join(missing), *caveats])})
    cut = min(_CUT_ORDER, key=lambda c: len(surface[c]))
    finding = Finding(category=RULE, risk=_risk(surface, entries),
                      evidence=_evidence(surface, cut, caveats),
                      id=combined_id(servers, file_tools))
    entry = AuditEntry(kind="config", name=snapshot.source or "config", findings=(finding,))
    return common.model_copy(update={"status": "triggered", "cut_point": cut, "entry": entry})
