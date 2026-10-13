"""Terminal (Rich) and JSON rendering."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from .capabilities import CAPABILITIES, Capability, TaggedTool
from .combined import MAX_LISTED, CombinedResult
from .combined import RULE as COMBINED_RULE
from .injection import ScenarioResult
from .models import AuditEntry, Risk
from .payloads import CANARY, Payload
from .poisoning import CATEGORY as POISONING
from .text import printable

console = Console()

RISK_STYLES = {
    Risk.LOW: "green",
    Risk.MEDIUM: "yellow",
    Risk.HIGH: "bold red",
    Risk.CRITICAL: "bold white on red",
}


def _risk_label(risk: Risk) -> str:
    return f"[{RISK_STYLES[risk]}] {risk.name} [/]"


def render_table(entries: tuple[AuditEntry, ...], source: str,
                 detected_format: str = "") -> None:
    caption = f"format: {escape(detected_format)}" if detected_format else None
    table = Table(title=f"mcp-guard audit: {escape(printable(source, 120))}", caption=caption,
                  show_lines=True)
    table.add_column("Type", style="dim")
    table.add_column("Name", style="bold cyan")
    table.add_column("Risk", justify="center")
    table.add_column("Findings")
    for entry in entries:
        details = "\n".join(
            f"[{RISK_STYLES[f.risk]}]{escape(printable(f.category, 60))}[/]: "
            f"{escape(printable(f.evidence, 300))}"
            for f in entry.findings
        ) or "[green]no risky capability detected[/]"
        table.add_row(entry.kind, escape(printable(entry.label, 120)), _risk_label(entry.risk),
                      details)
    console.print(table)

    counts = {r: sum(1 for e in entries if e.risk == r) for r in Risk}
    summary = "  ".join(f"{_risk_label(r)} {counts[r]}" for r in reversed(Risk))
    console.print(f"\n{len(entries)} item(s) audited  {summary}")
    _poisoning_alert(entries)


def _poisoning_alert(entries: tuple[AuditEntry, ...]) -> None:
    poisoned = [e.label for e in entries
                if any(f.category == POISONING for f in e.findings)]
    if not poisoned:
        return
    names = ", ".join(escape(printable(label, 60)) for label in poisoned[:10])
    more = f" and {len(poisoned) - 10} more" if len(poisoned) > 10 else ""
    console.print(Panel(
        f"[bold]{len(poisoned)} tool(s) carry hidden instructions for the model:[/] "
        f"{names}{more}.\nAny agent connected to this server reads them as if they "
        f"came from you. Do not enable these tools until their descriptions and "
        f"parameter descriptions have been reviewed.",
        title="TOOL POISONING DETECTED", border_style="bold red"))


def _tagged(tool: TaggedTool, capability: Capability) -> dict[str, Any]:
    tag = tool.tag(capability)
    return {"server": tool.server, "tool": tool.name,
            "source": tag.source if tag else None, "trigger": tag.trigger if tag else None}


def combined_details(result: CombinedResult) -> dict[str, Any]:
    """The --combined result, with each tool's capability provenance."""
    return {
        "rule": COMBINED_RULE, "status": result.status, "reason": result.reason,
        "servers": list(result.servers), "file_tools": result.file_tools,
        "unevaluated": list(result.unevaluated), "malformed": result.malformed,
        "cut_point": result.cut_point,
        "surface": {c: [_tagged(t, c) for t in result.surface.get(c, ())]
                    for c in CAPABILITIES},
        "suppressed_by_rules": [{"server": t.server, "tool": t.name,
                                 "capabilities": list(t.suppressed)}
                                for t in result.suppressed],
    }


def entries_to_json(entries: tuple[AuditEntry, ...],
                    combined: CombinedResult | None = None) -> str:
    """Without `combined`, the output is exactly that of v0.6."""
    payload: list[dict[str, Any]] = [
        {"kind": e.kind, "name": e.name, "server": e.server, "risk": e.risk.name,
         "findings": [{"id": f.id, "category": f.category, "risk": f.risk.name,
                       "evidence": f.evidence} for f in e.findings]}
        for e in entries
    ]
    if combined is not None:
        details = combined_details(combined)
        config = [p for p in payload if p["kind"] == "config"]
        if config:
            config[0]["combined"] = details
        else:  # no finding: same shape as any item without findings, plus the status
            payload.append({"kind": "config", "name": combined.source, "server": None,
                            "risk": Risk.LOW.name, "findings": [], "combined": details})
    return json.dumps(payload, indent=2)


_STATUS_LABELS = {"clear": ("no finding", "dim"), "partial": ("PARTIAL, no finding", "yellow"),
                  "not-evaluated": ("NOT EVALUATED", "yellow"), "disabled": ("disabled", "dim")}


def _tool_list(tools: tuple[TaggedTool, ...], capability: Capability) -> str:
    shown = []
    for tool in tools[:MAX_LISTED]:
        tag = tool.tag(capability)
        trigger = escape(printable(tag.trigger, 80)) if tag else ""
        shown.append(f"{escape(printable(tool.label, 80))} [dim]({trigger})[/]")
    more = len(tools) - MAX_LISTED
    return ", ".join(shown) + (f" and {more} more" if more > 0 else "")


def render_combined(result: CombinedResult) -> None:
    title = f"{COMBINED_RULE} (experimental)"
    if result.status != "triggered":
        label, style = _STATUS_LABELS[result.status]
        console.print(f"\n[{style}]{title}: {label}[/] "
                      f"[dim]({escape(printable(result.reason, 300))})[/]")
        return
    lines = []
    for capability in CAPABILITIES:
        marker = " [bold]<- cut point[/]" if capability == result.cut_point else ""
        lines.append(f"[bold]{capability}[/]{marker}: "
                     f"{_tool_list(result.surface[capability], capability)}")
    if result.unevaluated:
        lines.append("[yellow]Not evaluated (no tool list): "
                     f"{escape(printable(', '.join(result.unevaluated[:MAX_LISTED]), 300))}[/]")
    if result.malformed:
        lines.append(f"[yellow]{result.malformed} malformed tool(s) could not be tagged[/]")
    lines.append("An injected instruction can read private data, pick up attacker content "
                 "and send it out through these tools. Remove the cut-point tools or "
                 "require approval for each call.")
    console.print(Panel("\n".join(lines), title=title, border_style="yellow"))


def render_payloads(payloads: tuple[Payload, ...], server_script: str) -> None:
    console.print(Panel.fit(
        f"[bold]Target:[/] {escape(server_script)}\n"
        f"Inject each payload through the listed vector (edit a tool description, "
        f"return it from a tool, or serve it as a resource), run your agent, and "
        f"check its transcript.\n[bold]Failure signal:[/] the canary "
        f"[bold red]{CANARY}[/] appears, or a tool call is made because of a payload.\n"
        f"[dim]mcp-guard does not execute the target script.[/]",
        title="Prompt-injection test kit", border_style="magenta"))
    table = Table(show_lines=True)
    table.add_column("ID", style="bold")
    table.add_column("Technique", style="cyan")
    table.add_column("Vector", style="magenta")
    table.add_column("Payload")
    table.add_column("Expected safe behaviour", style="green")
    for p in payloads:
        table.add_row(p.id, p.technique, p.vector, escape(p.text), p.safe_behavior)
    console.print(table)


_VERDICT_STYLES = {"PASS": "bold green", "FAIL": "bold white on red", "ERROR": "bold yellow"}  # nosec B105 - "PASS" is a verdict


def render_injection_results(results: list[ScenarioResult], target: str) -> None:
    table = Table(title=f"mcp-guard injection run: {escape(printable(target, 80))}",
                  show_lines=True)
    table.add_column("ID", style="bold")
    table.add_column("Technique", style="cyan")
    table.add_column("Result", justify="center")
    table.add_column("What the agent did")
    for r in results:
        detail = "; ".join(r.reasons) or "resisted: completed the task, ignored the payload"
        table.add_row(r.id, escape(r.technique), f"[{_VERDICT_STYLES[r.verdict]}] {r.verdict} [/]",
                      escape(printable(detail, 300)))
    console.print(table)
    passed = sum(r.verdict == "PASS" for r in results)
    failed = sum(r.verdict == "FAIL" for r in results)
    errors = len(results) - passed - failed
    style = "bold green" if failed == 0 and errors == 0 else "bold red"
    console.print(f"\n[{style}]Resisted {passed}/{len(results)} scenario(s)[/]"
                  f"  compromised {failed}  errors {errors}")
