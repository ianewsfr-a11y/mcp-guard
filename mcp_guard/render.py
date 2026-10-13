"""Terminal (Rich) and JSON rendering."""

from __future__ import annotations

import json

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from .models import AuditEntry, Risk
from .payloads import CANARY, Payload
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


def entries_to_json(entries: tuple[AuditEntry, ...]) -> str:
    payload = [
        {"kind": e.kind, "name": e.name, "server": e.server, "risk": e.risk.name,
         "findings": [{"category": f.category, "risk": f.risk.name,
                       "evidence": f.evidence} for f in e.findings]}
        for e in entries
    ]
    return json.dumps(payload, indent=2)


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
