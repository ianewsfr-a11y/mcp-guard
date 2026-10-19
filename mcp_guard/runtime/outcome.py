"""What the journal keeps of a message for an OpenTelemetry export (issue #29).

Read from the message the inspector already parsed, never from its content:
- a `tools/call` or `prompts/get` request from the client: the tool or prompt
  name, only when it has the form of an MCP name (letters, digits, `_`, `-`,
  `.`, at most 128): a name is free text the client chose, and anything else
  is flagged, not copied;
- any request or notification, in either direction: its W3C `traceparent`
  from `params._meta` (MCP 2026-07-28, SEP-414). `tracestate` and `baggage`
  can carry arbitrary application data and are not kept; a malformed
  `traceparent` is flagged, not copied;
- `notifications/cancelled`, in either direction: the id of the request it
  cancels;
- a response: its outcome, following the OpenTelemetry MCP conventions, and
  the JSON-RPC error code. `isError: true` is a `tool_error` when the
  response answers a `tools/call`, or answers a request the journal did not
  see. `resultType` values are those of the 2026-07-28 specification
  (`complete`, absent meaning `complete`, and `input_required`). The error
  message and the result are never kept.
"""

from __future__ import annotations

import re
from typing import Any

MAX_FIELD = 128  # names and ids come from the peer: capped
_MAX_ID = 2**63  # a larger integer id is not kept (a long line for nothing)
_MAX_CODE = 2**31  # JSON-RPC error codes are small integers

# W3C Trace Context: version-traceid-parentid-flags, lower-case hex. Version
# ff is invalid; a later version may append fields, of which the first four
# are read (https://www.w3.org/TR/trace-context/#versioning-of-traceparent).
_TRACEPARENT = re.compile(
    r"(?P<version>[0-9a-f]{2})-(?P<trace>[0-9a-f]{32})-(?P<parent>[0-9a-f]{16})-[0-9a-f]{2}")
_NAME = re.compile(r"[A-Za-z0-9_.\-]{1,128}")
_NAMED = {"tools/call": "tool", "prompts/get": "prompt"}
_CANCELLED = "notifications/cancelled"
CLIENT, SERVER = "client->server", "server->client"
_MAX_PENDING = 1024  # requests waiting for their response, remembered


def peer_id(value: Any) -> str | int | None:
    """A JSON-RPC id as it can be journaled: strings capped, integers bounded."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        return value[:MAX_FIELD] or None
    return value if isinstance(value, int) and abs(value) < _MAX_ID else None


def traceparent(value: Any) -> str | None:
    """The valid part of a W3C traceparent, or None."""
    if not isinstance(value, str):
        return None
    match = _TRACEPARENT.match(value)
    if match is None or match["version"] == "ff":
        return None
    if set(match["trace"]) == {"0"} or set(match["parent"]) == {"0"}:
        return None
    if match["version"] == "00" and len(value) != match.end():
        return None
    if match["version"] != "00" and value[match.end():match.end() + 1] not in ("", "-"):
        return None
    return match.group(0)


def _trace(params: dict[str, Any]) -> dict[str, Any]:
    meta = params.get("_meta")
    if not isinstance(meta, dict) or "traceparent" not in meta:
        return {}
    valid = traceparent(meta["traceparent"])
    return {"traceparent": valid} if valid else {"traceparent_invalid": True}


def mcp_name(value: Any) -> str | None:
    """A tool or prompt name in the MCP charset, or None."""
    return value if isinstance(value, str) and _NAME.fullmatch(value) else None


def _name(field: str, value: Any) -> dict[str, Any]:
    name = mcp_name(value)
    return {field: name} if name else {f"{field}_invalid": True}


def _request(method: str, params: Any, direction: str) -> dict[str, Any]:
    if not isinstance(params, dict):
        return {}
    found = _trace(params)
    if method in _NAMED and direction == CLIENT:
        found.update(_name(_NAMED[method], params.get("name")))
    if method == _CANCELLED and (target := peer_id(params.get("requestId"))) is not None:
        found["cancels"] = target
    return found


def _result_outcome(result: Any, answers: str | None) -> str:
    if not isinstance(result, dict):
        return "unrecognized_result"
    kind = result.get("resultType", "complete")
    if kind == "input_required":
        return "input_required"
    if kind != "complete":
        return "unrecognized_result"
    tool = answers in (None, "tools/call")
    return "tool_error" if tool and result.get("isError") is True else "ok"


def _response(message: dict[str, Any], answers: str | None) -> dict[str, Any]:
    """An `error` member wins over a `result` one (both is malformed anyway)."""
    found: dict[str, Any] = {"answers": answers} if answers else {}
    if "error" in message:
        error = message["error"]
        code = error.get("code") if isinstance(error, dict) else None
        if isinstance(code, int) and not isinstance(code, bool) and abs(code) < _MAX_CODE:
            return {**found, "outcome": "error", "error_code": code}
        return {**found, "outcome": "error"}
    if "result" in message:
        return {**found, "outcome": _result_outcome(message["result"], answers)}
    return {**found, "outcome": "malformed"}


class Pending:
    """The method of each request seen, by (direction, id), so that a response
    says what it answers. Bounded: past the limit the oldest is forgotten."""

    def __init__(self) -> None:
        self._methods: dict[tuple[str, str | int], str] = {}

    def answers(self, direction: str, message: Any) -> str | None:
        """Remember a request; for a response, the method it answers."""
        if not isinstance(message, dict) or (ident := peer_id(message.get("id"))) is None:
            return None
        method = message.get("method")
        if isinstance(method, str):
            if len(self._methods) >= _MAX_PENDING:
                del self._methods[next(iter(self._methods))]
            self._methods[(direction, ident)] = method[:MAX_FIELD]
            return None
        asker = SERVER if direction == CLIENT else CLIENT
        return self._methods.pop((asker, ident), None)


def details(message: Any, direction: str, answers: str | None = None) -> dict[str, Any]:
    """The extra journal fields for one message (empty when none apply).
    `answers` is the method of the request a response answers, when known."""
    if not isinstance(message, dict):
        return {}
    method = message.get("method")
    if isinstance(method, str):
        return _request(method, message.get("params"), direction)
    if "id" in message:
        return _response(message, answers)
    return {}
