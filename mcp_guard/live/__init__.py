"""Live discovery: start (stdio) or contact (Streamable HTTP) each configured
server and fetch its real `tools/list`.

This is the only part of mcp-guard that executes anything, and it only runs
when the user passes `--live` and confirms the launch plan.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from ..analysis import audit_tool, sort_entries
from ..models import AuditEntry, Finding, Risk, ServerSpec
from ..rules import RuleSet
from .http import HttpTransport
from .launch import describe_launch, launch_warnings, resolve_executable
from .protocol import LiveError, Transport, list_tools
from .stdio import StdioTransport

__all__ = [
    "HttpTransport", "LiveError", "StdioTransport", "Transport", "add_live_results",
    "describe_launch", "fetch_tools", "launch_plan", "launch_warnings", "list_tools",
    "open_transport", "resolve_executable",
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


Fetcher = Callable[[ServerSpec, float], list[Any]]


def add_live_results(entries: tuple[AuditEntry, ...],
                     plan: list[tuple[str, ServerSpec]], ruleset: RuleSet,
                     timeout: float, fetch: Fetcher = fetch_tools,
                     ) -> tuple[AuditEntry, ...]:
    """Append each server's live tools; a server that fails gets a
    `live-discovery-failed` finding on its existing entry."""
    failures: dict[str, Finding] = {}
    tools: list[AuditEntry] = []
    for name, server in plan:
        try:
            raw_tools = fetch(server, timeout)
        except LiveError as exc:
            failures[name] = Finding(category="live-discovery-failed",
                                     risk=Risk.MEDIUM, evidence=str(exc))
            continue
        tools += [audit_tool(i, t, ruleset, server=name) for i, t in enumerate(raw_tools)]
    merged = [
        e.model_copy(update={"findings": ruleset.keep(e.findings + (failures[e.name],))})
        if e.kind == "server" and e.server is None and e.name in failures else e
        for e in entries
    ]
    return sort_entries(merged + tools, ruleset)
