"""What the TUI shows, built from an AuditRun. No Textual import here, so the
tree layout and the detail panel are testable on their own."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

from rich.console import Group as RichGroup
from rich.console import RenderableType
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from ..models import AuditEntry, Risk
from ..pipeline import AuditRun
from ..redact import redact_args, safe_url, stored_spec
from ..snapshot import ServerSnapshot, ToolSnapshot
from ..text import printable

LOCK_CATEGORIES = frozenset({"tool-changed", "server-changed", "tool-added", "server-added",
                             "tool-removed", "server-removed"})
_RISK_STYLES_DARK = {Risk.CRITICAL: "bold red", Risk.HIGH: "bold magenta",
                     Risk.MEDIUM: "yellow", Risk.LOW: "green"}
_RISK_STYLES_LIGHT = {Risk.CRITICAL: "bold red3", Risk.HIGH: "bold dark_magenta",
                      Risk.MEDIUM: "dark_goldenrod", Risk.LOW: "green4"}
STATIC_TOOLS = "Tools (from file)"


def risk_style(risk: Risk, dark: bool = True) -> str:
    return (_RISK_STYLES_DARK if dark else _RISK_STYLES_LIGHT)[risk]


@dataclass(frozen=True)
class Item:
    kind: Literal["server", "tool"]
    name: str
    server: str | None
    entry: AuditEntry | None
    snapshot: ToolSnapshot | ServerSnapshot | None = None
    lock_status: str | None = None  # None: no lock file in use

    @property
    def raw(self) -> dict[str, Any] | None:
        """The item as MCP describes it (a server spec is redacted)."""
        if isinstance(self.snapshot, ToolSnapshot):
            return self.snapshot.to_mcp()
        if isinstance(self.snapshot, ServerSnapshot) and self.snapshot.spec is not None:
            return stored_spec(self.snapshot.spec)
        return None

    @property
    def risk(self) -> Risk:
        return self.entry.risk if self.entry else Risk.LOW

    @property
    def label(self) -> str:
        return f"{self.server} > {self.name}" if self.server else self.name


@dataclass
class Group:
    title: str
    server: Item | None
    tools: list[Item] = field(default_factory=list)

    @property
    def risk(self) -> Risk:
        risks = [i.risk for i in ([self.server] if self.server else []) + self.tools]
        return max(risks, default=Risk.LOW)


def lock_status(entry: AuditEntry | None, lock_used: bool) -> str | None:
    if not lock_used:
        return None
    findings = [f for f in (entry.findings if entry else ()) if f.category in LOCK_CATEGORIES]
    if not findings:
        return "unchanged since the lock"
    return "; ".join(f"{f.category}: {f.evidence}" for f in findings)


def _tools_of(run: AuditRun, server: str | None) -> list[ToolSnapshot]:
    if server is None:
        return list(run.snapshot.tools)
    found = run.snapshot.server(server)
    return list(found.tools) if found else []


def _take(pool: list[ToolSnapshot], name: str) -> ToolSnapshot | None:
    """The first tool with that name, removed from the pool so that a second
    tool with the same name gets the second snapshot."""
    index = next((i for i, tool in enumerate(pool) if tool.name == name), None)
    return None if index is None else pool.pop(index)


def build_groups(run: AuditRun) -> list[Group]:
    """Servers with their live tools, then the tools listed in the file.
    Riskiest first inside each group."""
    lock_used = run.lock is not None
    groups: dict[str | None, Group] = {}
    pools: dict[str | None, list[ToolSnapshot]] = {}
    for server in run.snapshot.servers:
        groups[server.name] = Group(title=server.name, server=None)
    for entry in run.entries:
        key = entry.name if entry.kind == "server" else entry.server
        group = groups.setdefault(key, Group(title=key or STATIC_TOOLS, server=None))
        if entry.kind == "server":
            group.server = Item("server", entry.name, None, entry,
                                run.snapshot.server(entry.name),
                                lock_status(entry, lock_used))
        else:
            pool = pools.setdefault(key, _tools_of(run, key))
            group.tools.append(Item("tool", entry.name, entry.server, entry,
                                    _take(pool, entry.name), lock_status(entry, lock_used)))
    for group in groups.values():
        group.tools.sort(key=lambda item: item.risk, reverse=True)
    ordered = [g for k, g in groups.items() if k is not None]
    ordered.sort(key=lambda g: g.risk, reverse=True)
    return ordered + ([groups[None]] if None in groups else [])


def summary(run: AuditRun) -> str:
    counts = {r: sum(1 for e in run.entries if e.risk == r) for r in Risk}
    parts = "  ".join(f"{r.name} {counts[r]}" for r in reversed(Risk))
    return f"{printable(run.source, 60)}: {len(run.entries)} item(s)  {parts}"


# --- detail panel ---------------------------------------------------------------


def _server_display(server: ServerSnapshot) -> dict[str, Any]:
    """A server spec safe to show: args redacted, URL without query,
    env/header names only."""
    spec = server.spec
    if spec is None:
        return {"malformed": True}
    shown: dict[str, Any] = {}
    if spec.url:
        shown["url"] = safe_url(spec.url)
    if spec.command:
        shown["command"] = spec.command
        shown["args"] = redact_args([str(a) for a in spec.args])
    if spec.env:
        shown["env"] = sorted(map(str, spec.env))
    if spec.headers:
        shown["headers"] = sorted(map(str, spec.headers))
    return shown


def _json(value: Any, dark: bool) -> Syntax:
    text = json.dumps(value, indent=2, ensure_ascii=False, default=str)
    # ANSI themes use the terminal palette: no token backgrounds, readable on
    # dark and light terminals alike.
    return Syntax(printable_json(text), "json", theme="ansi_dark" if dark else "ansi_light",
                  word_wrap=True)


def printable_json(text: str) -> str:
    """JSON is shown as is, minus characters that could disturb the terminal
    (newlines from `indent` are kept)."""
    return "\n".join(printable(line) for line in text.split("\n"))


def detail(item: Item | None, dark: bool = True) -> RenderableType:
    if item is None:
        return Text("Select a server or a tool on the left.", style="dim")
    title = Text.assemble((f"{item.kind.upper()}  ", "dim"), (printable(item.label, 200), "bold"))
    risk = Text(f" {item.risk.name} ", style=f"reverse {risk_style(item.risk, dark)}")
    parts: list[RenderableType] = [title, Text.assemble("Risk: ", risk), Text("")]
    findings = item.entry.findings if item.entry else ()
    if findings:
        table = Table(show_header=True, header_style="bold", expand=True, show_lines=False)
        table.add_column("Category", no_wrap=True)
        table.add_column("Finding")
        for finding in findings:
            table.add_row(Text(printable(finding.category, 60),
                               style=risk_style(finding.risk, dark)),
                          Text(printable(finding.evidence, 400)))
        parts.append(table)
    else:
        parts.append(Text("No risky capability detected.", style=risk_style(Risk.LOW, dark)))
    parts += [Text(""), Text("Lock: ", style="bold")
              + Text(item.lock_status or "no lock file (use `mcp-guard lock`, then --lock)",
                     style="" if item.lock_status else "dim")]
    if isinstance(item.snapshot, ToolSnapshot):
        parts += _tool_detail(item.snapshot, dark)
    elif isinstance(item.snapshot, ServerSnapshot):
        parts += _server_detail(item.snapshot, dark)
    return RichGroup(*parts)


def _tool_detail(tool: ToolSnapshot, dark: bool) -> list[RenderableType]:
    description = printable(tool.description, 2000)
    parts: list[RenderableType] = [
        Text(""), Text("Description", style="bold"), Text(description or "(none)"),
        Text(""), Text("Input schema", style="bold"), _json(tool.input_schema, dark)]
    if tool.annotations:
        parts += [Text(""), Text("Annotations (declared by the server)", style="bold"),
                  _json(tool.annotations, dark)]
    return parts


def _server_detail(server: ServerSnapshot, dark: bool) -> list[RenderableType]:
    parts: list[RenderableType] = [Text(""), Text("Launch (secrets redacted)", style="bold"),
                                   _json(_server_display(server), dark)]
    if server.live_status == "captured":
        counts = (f"{len(server.tools)} tool(s), {len(server.resources)} resource(s), "
                  f"{len(server.prompts)} prompt(s)")
        parts += [Text(""), Text("Live capture: ", style="bold") + Text(counts)]
        parts += [Text(f"  {printable(w, 300)}", style="yellow")
                  for w in server.capture_warnings]
    return parts


def lock_report(run: AuditRun) -> RenderableType:
    if run.lock is None:
        return Text.assemble(
            ("No lock file in use.\n\n", "bold"),
            "Create one after reviewing your servers, then pass it with --lock:\n\n",
            ("  mcp-guard lock CONFIG [--live]\n  mcp-guard ui CONFIG --lock mcp-guard.lock",
             "cyan"))
    changes = [(e, f) for e in run.entries for f in e.findings if f.category in LOCK_CATEGORIES]
    head = Text.assemble(
        ("Lock file: ", "bold"), printable(str(run.lock_path), 200),
        f"\nMode: {run.lock.mode}   Created: {printable(run.lock.created, 40)}   "
        f"Locked: {len(run.lock.servers)} server(s), {len(run.lock.tools)} tool(s)\n\n")
    if not changes:
        return RichGroup(head, Text("No change since the lock.", style="bold green"))
    table = Table(expand=True, show_lines=True)
    table.add_column("Item")
    table.add_column("Change", no_wrap=True)
    table.add_column("Details")
    for entry, finding in changes:
        table.add_row(Text(printable(entry.label, 120)),
                      Text(finding.category, style=risk_style(finding.risk)),
                      Text(printable(finding.evidence, 300)))
    return RichGroup(head, Text(f"{len(changes)} change(s) since the lock:", style="bold"),
                     table)
