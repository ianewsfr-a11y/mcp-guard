"""Command-line interface."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import click
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape

from . import __version__, renderer
from .clients import System
from .clients import locations as client_locations
from .collector import capture_live, collect, launch_plan
from .diff import diff_snapshots
from .formats import load_config
from .injection import ScenarioResult, agent_command, build_scenarios, run_scenario
from .inline import SOURCE_LABEL, servers_from_cli
from .live import LiveError, LiveResults, describe_launch, launch_warnings
from .lock import (
    DEFAULT_LOCK,
    LOCK_VERSION,
    changes_since,
    fingerprint,
    migrated,
    read_lock,
    write_lock,
)
from .models import ConfigFormatError, Risk, ServerSpec
from .payloads import build_payloads
from .pipeline import AuditRun, Loader, run_audit
from .redact import secret_arg, secret_args
from .rules import DEFAULT_RULESET, load_ruleset
from .runtime.proxy import run_proxy
from .sarif import to_sarif
from .scan import scan as scan_machine
from .scan_report import render_scan, scan_to_json, scan_to_sarif
from .snapshot import MCPSnapshot
from .text import printable
from .ui import UIUnavailable, run_ui
from .ui import ensure_available as ensure_ui  # checked before any work in `ui`

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


def _live_results(snap: MCPSnapshot, timeout: float, assume_yes: bool) -> LiveResults:
    plan = launch_plan(snap)
    if not plan:
        stderr.print("[yellow]--live: no server to contact in this file.[/]")
        return {}
    _confirm_live(plan, assume_yes)
    with stderr.status("Fetching tools, resources and prompts from each server..."):
        return capture_live(plan, timeout)


def _static_snapshot(data: Any, source: str) -> MCPSnapshot:
    try:
        return collect(data, source)
    except ConfigFormatError as exc:
        raise InputError(str(exc)) from exc


def _load_input(config_file: Path | None, servers: tuple[str, ...]) -> tuple[Any, str]:
    """The config to audit and how to name it: a file, or --server values."""
    if bool(config_file) == bool(servers):
        raise InputError("give either CONFIG_FILE or one or more --server, not both")
    try:
        if config_file:
            return load_config(config_file), config_file.name
        return servers_from_cli(servers), SOURCE_LABEL
    except ConfigFormatError as exc:
        raise InputError(str(exc)) from exc


def _reload_live(snap: MCPSnapshot, confirmed: dict[str, ServerSpec],
                 timeout: float) -> LiveResults:
    """Live results for a refresh, without a new prompt: only servers whose
    spec is exactly the one the user confirmed are started again."""
    results: LiveResults = {}
    plan = []
    for name, spec in launch_plan(snap):
        if confirmed.get(name) == spec:
            plan.append((name, spec))
        else:
            results[name] = LiveError("added or changed since you confirmed --live; "
                                      "restart to approve it")
    return {**results, **capture_live(plan, timeout)}


def _collect(config_file: Path | None, servers: tuple[str, ...], rules_file: Path | None,
             live: bool, assume_yes: bool, timeout: float,
             lock_file: Path | None, combined: bool = False) -> tuple[AuditRun, Loader]:
    """The first audit run, and a loader that repeats it (for `ui` refresh)."""
    data, source = _load_input(config_file, servers)
    try:
        ruleset = load_ruleset(rules_file) if rules_file else DEFAULT_RULESET
    except ConfigFormatError as exc:
        raise InputError(str(exc)) from exc
    static = _static_snapshot(data, source)
    results = _live_results(static, timeout, assume_yes) if live else None
    confirmed = dict(launch_plan(static)) if live else {}

    def reload() -> AuditRun:
        fresh = load_config(config_file) if config_file else data
        fresh_live = (_reload_live(collect(fresh, source), confirmed, timeout)
                      if live else None)
        return run_audit(fresh, source, ruleset, fresh_live, lock_file, combined)

    try:
        return run_audit(data, source, ruleset, results, lock_file, combined), reload
    except ConfigFormatError as exc:
        raise InputError(str(exc)) from exc


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        click.echo(text)
    else:
        output.write_text(text + "\n", encoding="utf-8")
        stderr.print(f"Report written to {escape(str(output))}")


@cli.command()
@click.argument("config_file", required=False,
                type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--server", "servers", multiple=True, metavar="COMMAND_OR_URL",
              help='A server given inline instead of CONFIG_FILE, e.g. '
                   '"npx -y @modelcontextprotocol/server-memory" or an http(s) URL. '
                   'Repeatable.')
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
@click.option("--lock", "lock_file", type=click.Path(exists=True, dir_okay=False,
                                                     path_type=Path),
              help="Compare with a lock file from `mcp-guard lock` (rug-pull check).")
@click.option("--fail-on", type=_FAIL_CHOICES, default="none", show_default=True,
              help="Exit with code 1 if any item reaches this risk level (for CI).")
@click.option("--combined", is_flag=True,
              help="Experimental: also check what all active servers allow together "
                   "(private data + untrusted content + outbound channel). Needs --live "
                   "or a tools list.")
def inspect(config_file: Path | None, servers: tuple[str, ...], fmt: str, as_json: bool,
            output: Path | None, rules_file: Path | None, live: bool, assume_yes: bool,
            timeout: float, lock_file: Path | None, fail_on: str, combined: bool) -> None:
    """Audit an MCP client config or a tools list (JSON, JSONC or YAML), or
    servers given with --server."""
    fmt = "json" if as_json else fmt.lower()
    run, _ = _collect(config_file, servers, rules_file, live, assume_yes, timeout, lock_file,
                      combined)
    entries, ruleset = run.entries, run.ruleset

    if fmt == "table":
        renderer.render_table(entries, run.source,
                              run.snapshot.format if config_file else "--server")
        if run.combined is not None:
            renderer.render_combined(run.combined)
    elif fmt == "json":
        _emit(renderer.entries_to_json(entries, run.combined), output)
    else:
        text = config_file.read_text(encoding="utf-8-sig") if config_file else ""
        uri = _artifact_uri(config_file) if config_file else SOURCE_LABEL
        report = to_sarif(entries, ruleset, uri, text, run.combined)
        _emit(json.dumps(report, indent=2), output)

    if fail_on != "none" and any(e.risk >= Risk[fail_on.upper()] for e in entries):
        raise SystemExit(1)


def _system() -> System:
    """From sys.platform: platform.system() runs `cmd /c ver` on Windows before
    Python 3.12, and scan starts no process."""
    if sys.platform == "win32":
        return "Windows"
    return "Darwin" if sys.platform == "darwin" else "Linux"


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="JSON report.")
@click.option("--sarif", "as_sarif", is_flag=True, help="SARIF 2.1.0 report.")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path),
              help="Write the json/sarif report to this file.")
@click.option("--fail-on", type=_FAIL_CHOICES, default="high", show_default=True,
              help="Exit with code 1 if a server reaches this risk level.")
def scan(as_json: bool, as_sarif: bool, output: Path | None, fail_on: str) -> None:
    """Audit the MCP configs of known clients on this machine (Claude Desktop,
    Claude Code, Cursor, VS Code, Windsurf, Zed, Continue, Cline, Roo Code)
    and of the current directory. Static: no server is started or contacted."""
    if as_json and as_sarif:
        raise InputError("choose --json or --sarif, not both")
    if output is not None and not (as_json or as_sarif):
        raise InputError("-o needs --json or --sarif")
    searched = client_locations(Path.home(), Path.cwd(), os.environ, _system())
    result = scan_machine(searched, DEFAULT_RULESET)
    unread = [c for c in result.configs if c.status == "error"]
    if unread:
        stderr.print(f"[yellow]warning: {len(unread)} config(s) could not be read; their "
                     "servers were not audited.[/]")
    if as_json:
        _emit(scan_to_json(result), output)
    elif as_sarif:
        _emit(json.dumps(scan_to_sarif(result, DEFAULT_RULESET), indent=2), output)
    else:
        render_scan(result)
    if fail_on != "none" and any(s.risk >= Risk[fail_on.upper()] for s in result.servers):
        raise SystemExit(1)


@cli.command()
@click.argument("config_file", required=False,
                type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--server", "servers", multiple=True, metavar="COMMAND_OR_URL",
              help='A server given inline instead of CONFIG_FILE, e.g. '
                   '"npx -y @modelcontextprotocol/server-memory" or an http(s) URL. '
                   'Repeatable.')
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path),
              default=DEFAULT_LOCK, show_default=True, help="Lock file to write.")
@click.option("--live", is_flag=True,
              help="Also fingerprint the tools each server really serves.")
@click.option("--yes", "assume_yes", is_flag=True,
              help="Do not ask for confirmation before --live.")
@click.option("--timeout", type=click.FloatRange(min=1), default=20, show_default=True,
              help="Seconds to wait for each server in --live mode.")
@click.option("--update", is_flag=True,
              help="Rewrite the existing lock (-o) in the current format. Refused if "
                   "anything changed since it was written: review with inspect --lock, "
                   "then run lock without --update.")
def lock(config_file: Path | None, servers: tuple[str, ...], output: Path, live: bool,
         assume_yes: bool, timeout: float, update: bool) -> None:
    """Fingerprint servers and tools into a lock file, to detect rug pulls later."""
    data, source = _load_input(config_file, servers)
    static = _static_snapshot(data, source)
    results = _live_results(static, timeout, assume_yes) if live else None
    failed = {n: r for n, r in (results or {}).items() if isinstance(r, LiveError)}
    if failed:
        details = "; ".join(f"{printable(n, 60)}: {e}" for n, e in failed.items())
        raise InputError(f"cannot lock, some servers could not be reached: {details}")
    if update:
        _update_lock(collect(data, source, results), output)
        return
    snap = fingerprint(collect(data, source, results), pins=True)
    write_lock(snap, output)
    _warn_secret_args(static)
    again = " --live" if live else ""
    target = (str(config_file) if config_file
              else " ".join(f'--server "{v}"' for v in servers))
    stderr.print(f"Locked {len(snap.servers)} server(s) and {len(snap.tools)} tool(s) "
                 f"({snap.mode} mode) in {escape(str(output))}.\n"
                 f"Commit it, then check with: mcp-guard inspect "
                 f"{escape(printable(target, 300))} --lock {escape(str(output))}{again}")


def _warn_secret_args(snap: MCPSnapshot) -> None:
    """The pin keeps arguments as a salted HMAC whose salt is in the lock:
    a guessable secret among them can be recovered by whoever reads it."""
    for server in snap.servers:
        if server.spec is None:
            continue
        args = [str(a) for a in server.spec.args]
        if any(secret_arg(a, p) for a, p in zip(args, [None, *args])) or secret_args(args):
            stderr.print(f"[yellow]warning: {escape(printable(server.name, 60))}: an argument "
                         "looks secret. The lock masks it, but its HMAC salt is in the same "
                         "file, so a guessable value can be recovered: pass it through an "
                         "env variable instead.[/]")


def _update_lock(current: MCPSnapshot, path: Path) -> None:
    """Migrate a lock to the current format, only if nothing changed: a
    migration must never approve a rug pull silently."""
    if not path.exists():
        raise InputError(f"--update needs an existing lock file: {path} not found")
    try:
        locked = read_lock(path)
        pending = changes_since(locked, current, DEFAULT_RULESET)
    except ConfigFormatError as exc:
        raise InputError(str(exc)) from exc
    if pending:
        listed = "; ".join(f"{printable(label, 60)}: {f.category}" for label, f in pending[:10])
        more = f" and {len(pending) - 10} more" if len(pending) > 10 else ""
        raise InputError(f"{len(pending)} change(s) since {path} was written ({listed}{more}). "
                         f"Review them with `inspect --lock`, then run `lock` without "
                         f"--update to approve them.")
    write_lock(migrated(locked, current), path)
    stderr.print(f"Updated {escape(str(path))} from format {locked.version} to "
                 f"{LOCK_VERSION}: no change since it was written.")


@cli.command()
@click.argument("config_file", required=False,
                type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--server", "servers", multiple=True, metavar="COMMAND_OR_URL",
              help="A server given inline instead of CONFIG_FILE. Repeatable.")
@click.option("--rules", "rules_file", type=click.Path(exists=True, dir_okay=False,
                                                       path_type=Path),
              help="Custom rules file (YAML or JSON).")
@click.option("--live", is_flag=True,
              help="Start/contact each server and explore its real tools.")
@click.option("--yes", "assume_yes", is_flag=True,
              help="Do not ask for confirmation before --live.")
@click.option("--timeout", type=click.FloatRange(min=1), default=20, show_default=True,
              help="Seconds to wait for each server in --live mode.")
@click.option("--lock", "lock_file", type=click.Path(exists=True, dir_okay=False,
                                                     path_type=Path),
              help="Show changes since this lock file (rug-pull check).")
def ui(config_file: Path | None, servers: tuple[str, ...], rules_file: Path | None,
       live: bool, assume_yes: bool, timeout: float, lock_file: Path | None) -> None:
    """Explore an audit interactively: servers and tools on the left, details
    (findings, input schema, lock status) on the right.

    Keys: arrows to move, Tab to switch pane, R refresh, L lock report,
    T light/dark, Q quit.
    """
    try:
        ensure_ui()  # before any work: --live must not start servers for nothing
    except UIUnavailable as exc:
        raise click.ClickException(str(exc)) from exc
    run, reload = _collect(config_file, servers, rules_file, live, assume_yes, timeout,
                           lock_file)
    run_ui(run, reload)


def _confirm_run(target: Path, executable: str, args: list[str], count: int,
                 assume_yes: bool) -> None:
    command = " ".join([executable, *args])
    stderr.print(f"[bold yellow]--run will start this agent {count} time(s):[/] "
                 f"{escape(printable(command, 300))}")
    stderr.print("[dim]It runs with your user's permissions and may call paid APIs.[/]")
    if not assume_yes:
        click.confirm("Continue?", abort=True, err=True)


def _run_injection(target: Path, only: str | None, timeout: float,
                   assume_yes: bool) -> list[ScenarioResult]:
    scenarios = build_scenarios()
    if only:
        wanted = {s.strip().upper() for s in only.split(",") if s.strip()}
        unknown = wanted - {s.id for s in scenarios}
        if unknown:
            raise InputError(f"unknown scenario id(s): {', '.join(sorted(unknown))}")
        scenarios = tuple(s for s in scenarios if s.id in wanted)
    executable, args = agent_command(target)
    _confirm_run(target, executable, args, len(scenarios), assume_yes)
    results = []
    with stderr.status("Running injection scenarios...") as status:
        for scenario in scenarios:
            status.update(f"Running {scenario.id} ({scenario.payload.technique})...")
            results.append(run_scenario(executable, args, scenario, timeout))
    return results


@cli.command("test-injection")
@click.argument("target", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--run", is_flag=True,
              help="Run TARGET as an agent (mcp-guard-harness/1 over stdio) against "
                   "every payload and report what it did.")
@click.option("--only", metavar="IDS", help="With --run: comma-separated scenario ids.")
@click.option("--timeout", type=click.FloatRange(min=1), default=60, show_default=True,
              help="With --run: seconds per scenario.")
@click.option("--yes", "assume_yes", is_flag=True,
              help="With --run: do not ask for confirmation.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
def test_injection(target: Path, run: bool, only: str | None, timeout: float,
                   assume_yes: bool, as_json: bool) -> None:
    """Prompt-injection kit for agents.

    Without --run, prints the payloads to inject by hand. With --run, plays a
    hostile MCP server against the agent script TARGET and exits with 1 if it
    was compromised in any scenario (2 if a scenario could not run).
    """
    if not run:
        payloads = build_payloads()
        if as_json:
            click.echo(json.dumps([p.model_dump() for p in payloads], indent=2))
        else:
            renderer.render_payloads(payloads, str(target))
        return
    results = _run_injection(target, only, timeout, assume_yes)
    if as_json:
        click.echo(json.dumps([r.model_dump() for r in results], indent=2))
    else:
        renderer.render_injection_results(results, target.name)
    verdicts = {r.verdict for r in results}
    if "FAIL" in verdicts:
        raise SystemExit(1)
    if "ERROR" in verdicts:
        raise SystemExit(2)


# --- snapshot ---------------------------------------------------------------------

DEFAULT_SNAPSHOT = "mcp-guard.snapshot.json"
_DIFF_FORMATS = click.Choice(["table", "json"], case_sensitive=False)


@cli.group()
def snapshot() -> None:
    """Save captures of your MCP setup and compare them over time."""


@snapshot.command("save")
@click.argument("config_file", required=False,
                type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--server", "servers", multiple=True, metavar="COMMAND_OR_URL",
              help="A server given inline instead of CONFIG_FILE. Repeatable.")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path),
              default=DEFAULT_SNAPSHOT, show_default=True, help="Snapshot file to write.")
@click.option("--live", is_flag=True,
              help="Also capture the tools, resources and prompts each server serves.")
@click.option("--yes", "assume_yes", is_flag=True,
              help="Do not ask for confirmation before --live.")
@click.option("--timeout", type=click.FloatRange(min=1), default=20, show_default=True,
              help="Seconds to wait for each server in --live mode.")
def snapshot_save(config_file: Path | None, servers: tuple[str, ...], output: Path,
                  live: bool, assume_yes: bool, timeout: float) -> None:
    """Capture servers and tools into a snapshot file (secrets redacted)."""
    if config_file and output.resolve() == config_file.resolve():
        raise InputError("the snapshot would overwrite CONFIG_FILE: pick another -o")
    data, source = _load_input(config_file, servers)
    static = _static_snapshot(data, source)
    results = _live_results(static, timeout, assume_yes) if live else None
    snap = collect(data, source, results) if live else static
    _write(output, snap.to_json())
    failed = [s.name for s in snap.servers if s.live_status == "failed"]
    if failed:
        stderr.print(f"[yellow]warning: not reached, saved as failed: "
                     f"{escape(printable(', '.join(failed), 300))}[/]")
    tools = sum(1 for _ in snap.all_tools())
    stderr.print(f"Saved {len(snap.servers)} server(s) and {tools} tool(s) ({snap.mode} mode) "
                 f"in {escape(str(output))}, digest {snap.digest[:12]}.")


def _write(path: Path, text: str) -> None:
    """Write a report or snapshot; an unwritable path is an input error."""
    try:
        path.write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot write {path}: {exc.strerror or exc}") from exc


MAX_SNAPSHOT_DEPTH = 64  # real schemas are a few levels deep


def _depth(value: Any) -> int:
    """Nesting depth of parsed JSON, computed without recursion."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        node, level = stack.pop()
        deepest = max(deepest, level)
        if isinstance(node, dict):
            stack += [(child, level + 1) for child in node.values()]
        elif isinstance(node, list):
            stack += [(child, level + 1) for child in node]
    return deepest


def _read_snapshot(path: Path) -> MCPSnapshot:
    """A snapshot file, fully validated: bounded nesting, valid model, and it
    serializes back (so a crafted file fails here, not in the middle of a diff)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if _depth(data) > MAX_SNAPSHOT_DEPTH:
            raise ValueError(f"JSON nested deeper than {MAX_SNAPSHOT_DEPTH} levels")
        snap = MCPSnapshot.model_validate(data)
        _ = snap.digest
        return snap
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"cannot read snapshot {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not an mcp-guard snapshot (invalid JSON: {exc})") from exc
    except ValidationError as exc:
        raise InputError(f"{path} is not an mcp-guard snapshot "
                         f"({exc.error_count()} error(s), first: "
                         f"{printable(str(exc.errors()[0]['msg']), 200)})") from exc
    except (ValueError, RecursionError) as exc:
        raise InputError(f"{path} is not a usable snapshot: "
                         f"{printable(str(exc), 200)}") from exc


@snapshot.command("diff")
@click.argument("old", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("new", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--format", "fmt", type=_DIFF_FORMATS, default="table", show_default=True,
              help="`json` is a structured export for CI or other tools.")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path),
              help="Write the json report to this file.")
@click.option("--rules", "rules_file", type=click.Path(exists=True, dir_okay=False,
                                                       path_type=Path),
              help="Custom rules file, used to rate both snapshots.")
@click.option("--combined", is_flag=True,
              help="Also compare the experimental agent-exfiltration-surface result.")
@click.option("--exit-code", is_flag=True,
              help="Exit with code 1 when the attack surface changed (like git diff).")
def snapshot_diff(old: Path, new: Path, fmt: str, output: Path | None,
                  rules_file: Path | None, combined: bool, exit_code: bool) -> None:
    """Compare two snapshots: servers and tools added, removed or changed
    (description, input schema, annotations, risk), possible rug pulls."""
    if output and fmt.lower() != "json":
        raise click.UsageError("-o writes the json report: add --format json")
    try:
        ruleset = load_ruleset(rules_file) if rules_file else DEFAULT_RULESET
    except ConfigFormatError as exc:
        raise InputError(str(exc)) from exc
    before, after = _read_snapshot(old), _read_snapshot(new)
    try:
        diff = diff_snapshots(before, after, ruleset, combined)
    except (ValueError, RecursionError) as exc:  # e.g. a hand-edited tool that no longer validates
        raise InputError(f"cannot compare these snapshots: {printable(str(exc), 300)}") from exc
    if fmt.lower() == "json":
        report = renderer.diff_to_json(diff)
        if output:
            _write(output, report)
            stderr.print(f"Report written to {escape(str(output))}")
        else:
            click.echo(report)
    else:
        renderer.render_diff(diff)
    if exit_code and diff.changed:
        raise SystemExit(1)


# --- proxy ------------------------------------------------------------------------


@cli.command(context_settings={"ignore_unknown_options": True,
                               "allow_interspersed_args": False})
@click.option("--lock", "lock_file", type=click.Path(dir_okay=False, path_type=Path),
              help="Compare what the server declares with this lock (from `lock --live`).")
@click.option("--record", "record_file", type=click.Path(dir_okay=False, path_type=Path),
              help="Append a JSON-lines journal of the messages (sizes and hashes).")
@click.option("--record-bodies", is_flag=True,
              help="Also keep full messages in the journal (can contain secrets).")
@click.option("--server-name", help="The lock entry of this server, when it is ambiguous.")
@click.argument("command", nargs=-1, required=True, type=click.UNPROCESSED)
def proxy(lock_file: Path | None, record_file: Path | None, record_bodies: bool,
          server_name: str | None, command: tuple[str, ...]) -> None:
    """Run a stdio MCP server through mcp-guard: `mcp-guard proxy -- npx -y pkg`.

    Every byte is passed on unchanged. What the server declares (tools,
    annotations, identity) is compared with the lock and within the session,
    and differences are reported on stderr, prefixed `mcp-guard:`. The proxy
    prevents nothing; it makes changes visible.
    """
    raise SystemExit(run_proxy(command[0], list(command[1:]), lock_file, record_file,
                               record_bodies, server_name))
