"""Live discovery: start (stdio) or contact (Streamable HTTP) each configured
server and fetch its real `tools/list` (plus `resources/list` and
`prompts/list` when it declares them, for the snapshot).

This is the only part of mcp-guard that executes anything, and it only runs
when the user passes `--live` and confirms the launch plan.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from ..analysis import audit_tool, sort_entries, with_findings
from ..models import AuditEntry, Finding, Risk, ServerSpec
from ..rules import RuleSet
from .http import HttpTransport
from .launch import describe_launch, launch_warnings, resolve_executable
from .protocol import Capture, LiveError, Transport, capture, list_tools
from .stdio import StdioTransport

__all__ = [
    "Capture", "Fetcher", "HttpTransport", "LiveError", "LiveResults", "StdioTransport", "Transport",
    "add_live_results", "capture", "capture_server", "describe_launch", "fetch_all",
    "fetch_tools", "launch_plan",
    "launch_warnings", "list_tools", "merge_live_results", "open_transport",
    "resolve_executable",
]


def open_transport(server: ServerSpec, timeout: float) -> Transport:
    if server.url:
        headers = {str(k): str(v) for k, v in server.headers.items()}
        return HttpTransport(server.url, headers, timeout)
    if server.command:
        env = {str(k): str(v) for k, v in server.env.items()}
        executable = resolve_executable(server.command)
        return StdioTransport(executable, [str(a) for a in server.args], env, timeout)
    raise LiveError("no `command` or `url` to connect to")


def fetch_tools(server: ServerSpec, timeout: float) -> list[Any]:
    transport = open_transport(server, timeout)
    try:
        return list_tools(transport)
    finally:
        transport.close()


def capture_server(server: ServerSpec, timeout: float) -> Capture:
    transport = open_transport(server, timeout)
    try:
        return capture(transport)
    finally:
        transport.close()


def launch_plan(servers: dict[str, Any]) -> list[tuple[str, ServerSpec]]:
    """Servers live discovery would contact, skipping disabled and malformed ones."""
    plan = []
    for name, raw in servers.items():
        if isinstance(raw, dict) and raw.get("disabled") is True:
            continue
        try:
            plan.append((name, ServerSpec.model_validate(raw)))
        except ValidationError:
            continue
    return plan


Fetcher = Callable[[ServerSpec, float], "list[Any] | Capture"]
# per server: its tools (fetch_tools), a full Capture (capture_server), or the error
LiveResults = dict[str, "list[Any] | Capture | LiveError"]


def fetch_all(plan: list[tuple[str, ServerSpec]], timeout: float,
              fetch: Fetcher = fetch_tools) -> LiveResults:
    """What each server returned (see `fetch`), or the error that prevented it."""
    results: LiveResults = {}
    for name, server in plan:
        try:
            results[name] = fetch(server, timeout)
        except LiveError as exc:
            results[name] = exc
    return results


# Kept for API compatibility (v0.2+): the audit itself now goes through
# collector -> MCPSnapshot -> analyzer.


def merge_live_results(entries: tuple[AuditEntry, ...], results: LiveResults,
                       ruleset: RuleSet) -> tuple[AuditEntry, ...]:
    """Append each server's live tools; a server that failed gets a
    `live-discovery-failed` finding on its existing entry."""
    failures: dict[tuple[str, str], tuple[Finding, ...]] = {}
    tools: list[AuditEntry] = []
    for name, outcome in results.items():
        if isinstance(outcome, LiveError):
            failures[("server", name)] = (Finding(
                category="live-discovery-failed", risk=Risk.MEDIUM, evidence=str(outcome)),)
        else:
            raw = outcome.tools if isinstance(outcome, Capture) else outcome
            tools += [audit_tool(i, t, ruleset, server=name) for i, t in enumerate(raw)]
    return sort_entries(list(with_findings(entries, failures, ruleset)) + tools, ruleset)


def add_live_results(entries: tuple[AuditEntry, ...],
                     plan: list[tuple[str, ServerSpec]], ruleset: RuleSet,
                     timeout: float, fetch: Fetcher = fetch_tools,
                     ) -> tuple[AuditEntry, ...]:
    return merge_live_results(entries, fetch_all(plan, timeout, fetch), ruleset)
