"""MCP handshake and paginated tools/list, independent of the transport."""

from __future__ import annotations

from typing import Any, Protocol

from .. import __version__
from ..text import printable

PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 50
MAX_TOOLS = 5_000
MAX_SERVER_TEXT = 200
_CLIENT_INFO = {"name": "mcp-guard", "version": __version__}


class LiveError(Exception):
    """A server could not be started, reached, or did not answer correctly.
    Messages never embed raw exception text, URLs with credentials or
    unbounded server-controlled strings."""


class Transport(Protocol):
    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]: ...
    def notify(self, method: str) -> None: ...
    def close(self) -> None: ...


def server_text(value: Any) -> str:
    """A server-controlled string, made safe and short for a report."""
    return printable(str(value), MAX_SERVER_TEXT)


def error_name(exc: BaseException) -> str:
    """Describe an exception without its message (which may hold a URL,
    a path or a token): `ConnectionRefusedError: Connection refused`."""
    reason = getattr(exc, "reason", None)
    if isinstance(reason, OSError):
        exc = reason
    strerror = exc.strerror if isinstance(exc, OSError) else None
    return f"{type(exc).__name__}: {strerror}" if strerror else type(exc).__name__


def result_of(message: dict[str, Any], method: str) -> dict[str, Any]:
    if "error" in message:
        error = message["error"]
        detail = error.get("message", "") if isinstance(error, dict) else error
        raise LiveError(f"{method} failed: {server_text(detail)}")
    result = message.get("result")
    if not isinstance(result, dict):
        raise LiveError(f"{method} returned no result object")
    return result


def list_tools(transport: Transport) -> list[Any]:
    init = transport.request("initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": _CLIENT_INFO,
    })
    transport.notify("notifications/initialized")
    capabilities = init.get("capabilities")
    if isinstance(capabilities, dict) and "tools" not in capabilities:
        return []
    tools: list[Any] = []
    cursor = None
    for _ in range(MAX_PAGES):
        page = transport.request("tools/list", {"cursor": cursor} if cursor else {})
        if not isinstance(page.get("tools"), list):
            raise LiveError("tools/list returned no `tools` array")
        tools += page["tools"]
        if len(tools) > MAX_TOOLS:
            raise LiveError(f"server returned more than {MAX_TOOLS} tools")
        cursor = page.get("nextCursor")
        if not cursor:
            break
    return tools
