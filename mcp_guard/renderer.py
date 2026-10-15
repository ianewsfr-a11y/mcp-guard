"""Terminal (Rich) and JSON rendering: audits, the --combined rule, snapshot
diffs and injection runs."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .capabilities import CAPABILITIES, Capability, TaggedTool
from .combined import MAX_LISTED, CombinedResult
from .combined import RULE as COMBINED_RULE
from .diff import CombinedDiff, FieldChange, ItemDiff, SnapshotDiff
from .injection import ScenarioResult
from .markup import escape
from .models import AuditEntry, Risk
from .payloads import CANARY, Payload
from .poisoning import CATEGORY as POISONING
from .text import printable, visible

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


# --- snapshot diff ----------------------------------------------------------------

_CHANGE_STYLES = {"added": ("+", "green"), "removed": ("-", "red"), "changed": ("~", "yellow")}
_MAX_PATHS_SHOWN = 8


def diff_to_json(diff: SnapshotDiff) -> str:
    """Structured diff for CI or other tools (format `mcp-guard-diff/1`)."""
    payload = diff.model_dump(mode="json")
    payload.update({"identical": diff.identical, "changed": diff.changed,
                    "unclassified": diff.unclassified, "counts": diff.counts()})
    for item, data in zip(diff.items, payload["items"]):
        data.update({"label": item.label, "rug_pull": item.rug_pull})
    if diff.combined is not None:
        payload["combined"]["changed"] = diff.combined.changed
    return json.dumps(payload, indent=2)


def _short(value: Any, limit: int = 120) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return escape(printable(text, limit))


def _path_lines(change: FieldChange) -> list[str]:
    lines = []
    for path in change.paths[:_MAX_PATHS_SHOWN]:
        sign, style = _CHANGE_STYLES[path.op]
        if path.op == "changed":
            detail = f"{_short(path.old, 60)} -> {_short(path.new, 60)}"
        else:
            detail = _short(path.new if path.op == "added" else path.old, 80)
        lines.append(f"[{style}]{sign} {escape(printable(path.path, 80))}[/]: {detail}")
    hidden = len(change.paths) - _MAX_PATHS_SHOWN
    if hidden > 0 or change.truncated:
        lines.append(f"[dim]... and {max(hidden, 0)} more path change(s)"
                     f"{', truncated' if change.truncated else ''}[/]")
    return lines


_WINDOW = 300


def _text_window(old: str, new: str) -> tuple[str, str]:
    """Both texts from a little before their first difference, so an edit
    after the first 300 characters is still visible."""
    start = next((i for i, (a, b) in enumerate(zip(old, new)) if a != b),
                 min(len(old), len(new)))
    begin = max(0, start - 40)
    prefix = "..." if begin else ""
    return prefix + old[begin:begin + _WINDOW], prefix + new[begin:begin + _WINDOW]


def _text_lines(change: FieldChange) -> list[str]:
    old, new = str(change.old or ""), str(change.new or "")
    shown_old, shown_new = _text_window(old, new)
    lines = [f"[bold]{change.field}[/] [dim]({len(old)} -> {len(new)} chars)[/]",
             f"[red]- {escape(printable(shown_old))}[/]",
             f"[green]+ {escape(printable(shown_new))}[/]"]
    if visible(old) == visible(new):
        lines.append("[bold red]the texts differ only in invisible or control characters[/]")
    return lines


def _field_lines(change: FieldChange) -> list[str]:
    title = f"[bold]{change.field}[/]"
    if change.paths:
        return [title, *_path_lines(change)]
    if change.field in ("description", "instructions"):
        return _text_lines(change)
    return [f"{title}: {_short(change.old, 60)} -> {_short(change.new, 60)}"]


def _item_details(item: ItemDiff) -> str:
    lines: list[str] = []
    if item.rug_pull:
        lines.append("[bold red]possible rug pull: the tool kept its name but changed "
                     "what it tells the model[/]")
    for change in item.changes:
        lines += _field_lines(change)
    lines += [f"[red]+ finding {escape(c)}[/]" for c in item.findings_added]
    lines += [f"[green]- finding {escape(c)}[/]" for c in item.findings_removed]
    return "\n".join(lines) or "[dim]-[/]"


def _risk_cell(item: ItemDiff) -> str:
    old = f"[{RISK_STYLES[Risk[item.risk_old]]}]{item.risk_old}[/]" if item.risk_old else ""
    new = f"[{RISK_STYLES[Risk[item.risk_new]]}]{item.risk_new}[/]" if item.risk_new else ""
    if old and new and item.risk_old != item.risk_new:
        return f"{old} -> {new}"
    return new or old


def _combined_lines(combined: CombinedDiff) -> list[str]:
    def side(status: str, risk: str | None, cut: str | None) -> str:
        return status + (f" {risk}" if risk else "") + (f", cut point {cut}" if cut else "")

    lines = [(f"{side(combined.status_old, combined.risk_old, combined.cut_point_old)} -> "
             f"{side(combined.status_new, combined.risk_new, combined.cut_point_new)}")]
    if combined.id_old != combined.id_new and combined.id_old and combined.id_new:
        lines.append("[yellow]finding id changed: the set of servers involved changed[/]")
    for capability in CAPABILITIES:
        added = combined.tools_added.get(capability, ())
        removed = combined.tools_removed.get(capability, ())
        if added:
            lines.append(f"[red]+ {capability}: {_short(', '.join(added), 300)}[/]")
        if removed:
            lines.append(f"[green]- {capability}: {_short(', '.join(removed), 300)}[/]")
    return lines


def render_diff(diff: SnapshotDiff) -> None:
    console.print(
        f"[bold]snapshot diff[/] {escape(printable(diff.old_source, 60))} "
        f"[dim]({escape(printable(diff.old_captured_at, 30))}, {diff.old_digest[:12]})[/]"
        f" -> {escape(printable(diff.new_source, 60))} "
        f"[dim]({escape(printable(diff.new_captured_at, 30))}, {diff.new_digest[:12]})[/]")
    if not diff.changed:
        console.print("[bold green]No change in the attack surface[/] [dim](same content "
                      "digest; capture time and path are not content)[/]")
        return
    for change in diff.context:
        console.print(f"[bold yellow]{change.field} changed:[/] {_short(change.old, 80)} -> "
                      f"{_short(change.new, 80)}")
    if any(c.field == "mode" for c in diff.context):
        console.print("[yellow]Comparing a static and a live snapshot: live tools belong to "
                      "a server, file tools do not, so they show as removed and added.[/]")
    if diff.unclassified:
        console.print("[yellow]The content differs, but in nothing compared item by item "
                      "(e.g. the order of tools). Compare the files to see it.[/]")
    table = Table(show_lines=True)
    table.add_column("Change", no_wrap=True)
    table.add_column("Item", style="bold cyan")
    table.add_column("Risk", justify="center")
    table.add_column("Details")
    for item in diff.items:
        sign, style = _CHANGE_STYLES[item.category.split("-")[1]]
        label = item.label + (f" #{item.occurrence + 1}" if item.occurrence else "")
        table.add_row(f"[{style}]{sign} {item.category}[/]",
                      escape(printable(label, 120)), _risk_cell(item), _item_details(item))
    if diff.items:
        console.print(table)
    if diff.combined is not None and diff.combined.changed:
        console.print(Panel("\n".join(_combined_lines(diff.combined)),
                            title=f"{COMBINED_RULE} (experimental)", border_style="yellow"))
    counts = "  ".join(f"{category} {n}" for category, n in sorted(diff.counts().items()))
    console.print(f"\n{len(diff.items)} change(s)  {counts}")
