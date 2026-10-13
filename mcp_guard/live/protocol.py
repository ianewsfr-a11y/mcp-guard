"""MCP handshake and paginated tools/resources/prompts lists, independent of
the transport."""

from __future__ import annotations

from typing import Any, NamedTuple, Protocol

from .. import __version__
from ..text import printable

PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 50
MAX_TOOLS = 5_000
MAX_SERVER_TEXT = 200
MAX_CURSOR = 1_000
MAX_INSTRUCTIONS = 20_000
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


class Capture(NamedTuple):
    """What one server declared. Resources and prompts are optional: a failure
    to list them is kept in `warnings` and does not lose the tools."""

    tools: tuple[Any, ...]
    resources: tuple[Any, ...] = ()
    prompts: tuple[Any, ...] = ()
    warnings: tuple[str, ...] = ()
    instructions: str | None = None  # sent by the server at initialization
    identity: dict[str, Any] | None = None  # the initialize result, for serverInfo


def _initialize(transport: Transport) -> dict[str, Any]:
    init = transport.request("initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": _CLIENT_INFO,
    })
    transport.notify("notifications/initialized")
    return init


def _capabilities(init: dict[str, Any]) -> dict[str, Any] | None:
    capabilities = init.get("capabilities")
    return capabilities if isinstance(capabilities, dict) else None


def _handshake(transport: Transport) -> dict[str, Any] | None:
    return _capabilities(_initialize(transport))


def _declares(capabilities: dict[str, Any] | None, name: str) -> bool:
    # no capabilities object at all: assume tools only, as before
    return name == "tools" if capabilities is None else name in capabilities


def _paged(transport: Transport, method: str, key: str) -> list[Any]:
    items: list[Any] = []
    cursor = None
    for _ in range(MAX_PAGES):
        page = transport.request(method, {"cursor": cursor} if cursor else {})
        if not isinstance(page.get(key), list):
            raise LiveError(f"{method} returned no `{key}` array")
        if len(items) + len(page[key]) > MAX_TOOLS:
            raise LiveError(f"server returned more than {MAX_TOOLS} {key}")
        items += page[key]
        cursor = _next_cursor(page)
        if cursor is None:
            break
    return items


def _next_cursor(page: dict[str, Any]) -> str | None:
    """The next page's cursor. It is sent back to the server, so a
    non-string or oversized one is refused (loops are bounded by MAX_PAGES
    and MAX_TOOLS)."""
    cursor = page.get("nextCursor")
    if not cursor:
        return None
    if not isinstance(cursor, str) or len(cursor) > MAX_CURSOR:
        raise LiveError("server returned an invalid nextCursor")
    return cursor


def list_tools(transport: Transport) -> list[Any]:
    capabilities = _handshake(transport)
    return _paged(transport, "tools/list", "tools") if _declares(capabilities, "tools") else []


def capture(transport: Transport) -> Capture:
    """Tools, resources and prompts the server declares, in one session."""
    init = _initialize(transport)
    capabilities = _capabilities(init)
    instructions = init.get("instructions")
    tools = _paged(transport, "tools/list", "tools") if _declares(capabilities, "tools") else []
    lists: dict[str, list[Any]] = {"resources": [], "prompts": []}
    warnings: list[str] = []
    for key in lists:
        if not _declares(capabilities, key):
            continue
        try:
            lists[key] = _paged(transport, f"{key}/list", key)
        except LiveError as exc:
            warnings.append(f"{key}/list: {exc}")
    return Capture(tuple(tools), tuple(lists["resources"]), tuple(lists["prompts"]),
                   tuple(warnings),
                   instructions[:MAX_INSTRUCTIONS]
                   if isinstance(instructions, str) and instructions else None,
                   {k: init[k] for k in ("serverInfo", "capabilities", "protocolVersion")
                    if k in init} or None)
