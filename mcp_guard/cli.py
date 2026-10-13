"""Command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from . import __version__, render
from .analysis import audit
from .formats import discover, load_config
from .live import add_live_results, describe_launch, launch_plan, launch_warnings
from .models import AuditEntry, ConfigFormatError, Risk
from .payloads import build_payloads
from .rules import DEFAULT_RULESET, RuleSet, load_ruleset
from .sarif import to_sarif
from .text import printable

_FAIL_CHOICES = click.Choice(["none", "low", "medium", "high", "critical"],
                             case_sensitive=False)
_FORMATS = click.Choice(["table", "json", "sarif"], case_sensitive=False)

stderr = Console(stderr=True)


class InputError(click.ClickException):
    """Unreadable input. Exit code 2 keeps it distinct from `--fail-on` (1)."""

    exit_code = 2


@click.group()
@click.version_option(__version__, prog_name="mcp-guard")
def cli() -> None:
    """Minimalist security audit CLI for MCP servers and AI agents."""


def _artifact_uri(path: Path) -> str:
    """SARIF needs a path relative to the repository root (the cwd in CI)."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        stderr.print("[yellow]warning: the config is outside the current directory; "
                     "run from the repository root so code scanning can link findings.[/]")
        return path.resolve().as_posix()


def _confirm_live(plan: list, assume_yes: bool) -> None:
    stderr.print("[bold yellow]--live will start or contact these servers:[/]")
    for name, server in plan:
        stderr.print(f"  [cyan]{escape(printable(name, 80))}[/]: "
                     f"{escape(describe_launch(server))}")
        for warning in launch_warnings(server):
            stderr.print(f"    [bold red]warning:[/] {escape(warning)}")
    stderr.print("[dim]Only continue if you trust these commands: they run with "
                 "your user's permissions.[/]")
    if not assume_yes:
        click.confirm("Continue?", abort=True, err=True)


def _run_live(entries: tuple[AuditEntry, ...], servers: dict, ruleset: RuleSet,
              timeout: float, assume_yes: bool) -> tuple[AuditEntry, ...]:
    plan = launch_plan(servers)
    if not plan:
        stderr.print("[yellow]--live: no server to contact in this file.[/]")
        return entries
    _confirm_live(plan, assume_yes)
    with stderr.status("Fetching tools/list from each server..."):
        return add_live_results(entries, plan, ruleset, timeout)


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        click.echo(text)
    else:
        output.write_text(text + "\n", encoding="utf-8")
        stderr.print(f"Report written to {escape(str(output))}")


@cli.command()
@click.argument("config_file", type=click.Path(exists=True, dir_okay=False,
                                               path_type=Path))
@click.option("--format", "fmt", type=_FORMATS, default="table", show_default=True,
              help="Report format. `sarif` is for GitHub code scanning.")
@click.option("--json", "as_json", is_flag=True, hidden=True,
              help="Shortcut for --format json.")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path),
              help="Write the json/sarif report to this file.")
@click.option("--rules", "rules_file", type=click.Path(exists=True, dir_okay=False,
                                                       path_type=Path),
              help="Custom rules file (YAML or JSON).")
@click.option("--live", is_flag=True,
              help="Start/contact each server and audit its real tools/list.")
@click.option("--yes", "assume_yes", is_flag=True,
              help="Do not ask for confirmation before --live.")
@click.option("--timeout", type=click.FloatRange(min=1), default=20, show_default=True,
              help="Seconds to wait for each server in --live mode.")
@click.option("--fail-on", type=_FAIL_CHOICES, default="none", show_default=True,
              help="Exit with code 1 if any item reaches this risk level (for CI).")
def inspect(config_file: Path, fmt: str, as_json: bool, output: Path | None,
            rules_file: Path | None, live: bool, assume_yes: bool, timeout: float,
            fail_on: str) -> None:
    """Audit an MCP client config or a tools list (JSON, JSONC or YAML)."""
    fmt = "json" if as_json else fmt.lower()
    try:
        ruleset = load_ruleset(rules_file) if rules_file else DEFAULT_RULESET
        data = load_config(config_file)
        found = discover(data)
        entries = audit(data, ruleset)
    except ConfigFormatError as exc:
        raise InputError(str(exc)) from exc

    if live:
        entries = _run_live(entries, found.servers, ruleset, timeout, assume_yes)

    if fmt == "table":
        render.render_table(entries, config_file.name, found.format)
    elif fmt == "json":
        _emit(render.entries_to_json(entries), output)
    else:
        text = config_file.read_text(encoding="utf-8-sig")
        report = to_sarif(entries, ruleset, _artifact_uri(config_file), text)
        _emit(json.dumps(report, indent=2), output)

    if fail_on != "none" and any(e.risk >= Risk[fail_on.upper()] for e in entries):
        raise SystemExit(1)


@cli.command("test-injection")
@click.argument("server_script", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Output payloads as JSON.")
def test_injection(server_script: str, as_json: bool) -> None:
    """Print MCP-oriented prompt-injection payloads to test an agent."""
    payloads = build_payloads()
    if as_json:
        click.echo(json.dumps([p.model_dump() for p in payloads], indent=2))
    else:
        render.render_payloads(payloads, server_script)
