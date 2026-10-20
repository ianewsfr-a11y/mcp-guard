"""A proxy journal read back as spans, one per request (issue #29).

A request opens a span; what closes it sets its outcome: the response from
the other side, a `notifications/cancelled` from the side that asked, a new
request reusing its id (no response), or the end of the run (`server_exit`
set and not 0: the server stopped, a transport failure; otherwise no
response). A journal can hold several runs appended one after the other:
each `end` line closes one.

Trace context: a valid `traceparent` makes the span a child of the caller's
span in the caller's trace, unless `propagate` is off. Without one, the
request is a local root, marked so: since MCP 2026-07-28 a connection is not
a session, so requests are not grouped under one trace; `mcp_guard.run`
groups those of a run.

The journal is a file anyone may have edited: every field is checked again,
as the proxy checked it, and a line that is too long or not an entry is
skipped and counted. Bodies and unknown fields are never read. Span and
local trace ids derive from a salt and the entry's place in the journal,
never from the message: the same salt gives the same export.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from .outcome import CLIENT, SERVER, mcp_name, peer_id, traceparent

MAX_LINE = 1024 * 1024  # an entry without body is a few hundred bytes
MAX_OPEN = 100_000  # requests open at once in one run
MAX_SPANS = 200_000  # spans in one export
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_NS = 2**64
_METHOD = re.compile(r"[A-Za-z0-9_./\-]{1,128}")
_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,128}")
_RECORDED = frozenset({"ok", "input_required", "tool_error", "error",
                       "unrecognized_result", "malformed"})  # what the proxy writes
_ERRORS = {"ok": None, "input_required": None, "tool_error": "tool_error", "error": "_OTHER",
           "unrecognized_result": "unrecognized_result", "malformed": "malformed",
           "cancelled": "cancelled", "no_response": "mcp_guard.no_response",
           "transport_failure": "mcp_guard.transport_failure"}
Attribute = tuple[str, "str | int"]
Key = tuple[str, "str | int"]


@dataclass(frozen=True)
class Span:
    trace_id: str
    span_id: str
    parent_id: str | None
    name: str
    start_ns: int
    end_ns: int
    attributes: tuple[Attribute, ...]
    error: bool


@dataclass(frozen=True)
class Export:
    spans: tuple[Span, ...]
    skipped: int  # lines that are not journal entries, or too long
    unmatched: int  # responses and cancellations with no open request
    dropped: int  # requests not exported: too many open, or past MAX_SPANS
    lost: int = 0  # entries the proxy itself dropped (the `dropped` of its end lines)
    invalid_traceparents: int = 0  # requests whose traceparent was malformed


@dataclass(frozen=True)
class Options:
    salt: str = ""
    propagate: bool = True  # follow an incoming traceparent


def _ns(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    if moment.tzinfo is None:
        return None
    delta = moment - _EPOCH
    ns = (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    return ns if 0 <= ns < _MAX_NS else None


def _digest(*parts: object) -> str:
    return hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()


def _identity(item: dict[str, Any], seed: str, options: Options,
              ) -> tuple[str, str | None, str]:
    """(trace id, parent span id, origin) for a request."""
    found = traceparent(item.get("traceparent")) if options.propagate else None
    if found:
        _version, trace_id, parent, _flags = found.split("-")[:4]
        return trace_id, parent, "propagated"
    return _digest("trace", seed)[:32], None, "local"


def _target(method: str, item: dict[str, Any]) -> list[Attribute]:
    if method == "tools/call" and (tool := mcp_name(item.get("tool"))):
        return [("gen_ai.tool.name", tool), ("gen_ai.operation.name", "execute_tool")]
    if method == "prompts/get" and (prompt := mcp_name(item.get("prompt"))):
        return [("gen_ai.prompt.name", prompt)]
    return []


@dataclass(frozen=True)
class _Open:
    span: Span  # still without end, outcome and error
    key: Key


def _open(item: dict[str, Any], start: int, place: str, options: Options) -> _Open | None:
    ident = peer_id(item.get("id"))
    if ident is None:
        return None
    method = item["method"] if _METHOD.fullmatch(item["method"]) else "_OTHER"
    seed = f"{options.salt}:{place}"
    trace_id, parent, origin = _identity(item, seed, options)
    attrs: list[Attribute] = [("mcp.method.name", method), ("network.transport", "pipe")]
    if isinstance(ident, int) or _ID.fullmatch(ident):
        attrs.append(("jsonrpc.request.id", str(ident)))
    target = _target(method, item)
    attrs += [*target, ("mcp_guard.direction", item["direction"]),
              ("mcp_guard.trace.origin", origin), ("mcp_guard.run", int(place.split(":")[0]))]
    name = f"{method} {target[0][1]}" if target else method
    span = Span(trace_id, _digest("span", seed)[:16], parent, name, start, start,
                tuple(attrs), False)
    return _Open(span, (item["direction"], ident))


def _closed(opened: _Open, end: int, outcome: str, code: Any = None) -> Span:
    error_type = _ERRORS[outcome]
    attrs = [*opened.span.attributes, ("mcp_guard.outcome", outcome)]
    if outcome == "error":
        valid = isinstance(code, int) and not isinstance(code, bool) and abs(code) < 2**31
        if valid:
            error_type = str(code)
            attrs.append(("rpc.response.status_code", str(code)))
    if error_type:
        attrs.append(("error.type", error_type))
    return replace(opened.span, end_ns=max(end, opened.span.start_ns),
                   attributes=tuple(attrs), error=error_type is not None)


def _entry(text: str | None) -> tuple[dict[str, Any], int] | None:
    if text is None or len(text) > MAX_LINE:
        return None
    try:
        item = json.loads(text)
    except (ValueError, RecursionError):  # RecursionError: nesting deeper than the stack
        return None
    if not isinstance(item, dict) or (ts := _ns(item.get("ts"))) is None:
        return None
    if item.get("event") == "end":
        return item, ts
    if item.get("direction") not in (CLIENT, SERVER):
        return None
    method = item.get("method")
    return (item, ts) if method is None or isinstance(method, str) else None


def _invalid_trace(item: dict[str, Any]) -> bool:
    """Flagged by the proxy, or no longer valid in an edited journal: an
    upstream gateway or SDK that mangles the trace context shows here."""
    if item.get("traceparent_invalid") is True:
        return True
    return "traceparent" in item and traceparent(item["traceparent"]) is None


class _Reader:
    """Spans of one journal, run after run. Bounded by MAX_OPEN and MAX_SPANS."""

    def __init__(self, options: Options) -> None:
        self.options = options
        self.run = 1
        self.open: dict[Key, _Open] = {}
        self.cancelled: set[Key] = set()  # a late answer to these is expected
        self.spans: list[Span] = []
        self.unmatched = 0
        self.dropped = 0
        self.lost = 0
        self.invalid_traceparents = 0

    def finish(self, outcome: str, end: int) -> None:
        for opened in self.open.values():
            self.emit(_closed(opened, end, outcome))
        self.open, self.cancelled = {}, set()

    def emit(self, span: Span) -> None:
        if len(self.spans) < MAX_SPANS:
            self.spans.append(span)
        else:
            self.dropped += 1

    def request(self, item: dict[str, Any], ts: int, line: int) -> None:
        """Opens a span; `invalid_traceparents` counts only the spans kept."""
        opened = _open(item, ts, f"{self.run}:{line}", self.options)
        if opened is None:
            return
        previous = self.open.pop(opened.key, None)
        if previous is not None:  # its id is reused: it was never answered
            self.emit(_closed(previous, ts, "no_response"))
        if len(self.open) >= MAX_OPEN:
            self.dropped += 1
            return
        self.cancelled.discard(opened.key)
        self.open[opened.key] = opened
        if _invalid_trace(item):
            self.invalid_traceparents += 1

    def cancel(self, item: dict[str, Any], ts: int) -> None:
        target = peer_id(item.get("cancels"))
        key = (item["direction"], target) if target is not None else None
        found = self.open.pop(key, None) if key else None
        if found is None or key is None:
            self.unmatched += 1
            return
        if len(self.cancelled) < MAX_OPEN:
            self.cancelled.add(key)
        self.emit(_closed(found, ts, "cancelled"))

    def response(self, item: dict[str, Any], ts: int) -> None:
        ident = peer_id(item.get("id"))
        if ident is None:
            return
        key = (SERVER if item["direction"] == CLIENT else CLIENT, ident)
        found = self.open.pop(key, None)
        if found is None:
            if key in self.cancelled:
                self.cancelled.discard(key)
            else:
                self.unmatched += 1
            return
        outcome = item.get("outcome")
        outcome = outcome if isinstance(outcome, str) and outcome in _RECORDED else "malformed"
        self.emit(_closed(found, ts, outcome, item.get("error_code")))

    def step(self, item: dict[str, Any], ts: int, line: int) -> None:
        if item.get("event") == "end":
            code = item.get("server_exit")
            failed = isinstance(code, int) and not isinstance(code, bool) and code != 0
            lost = item.get("dropped")
            if isinstance(lost, int) and not isinstance(lost, bool) and 0 < lost < _MAX_NS:
                self.lost += lost
            self.finish("transport_failure" if failed else "no_response", ts)
            self.run += 1
        elif item.get("method") == "notifications/cancelled":
            self.cancel(item, ts)
        elif isinstance(item.get("method"), str):
            self.request(item, ts, line)
        else:
            self.response(item, ts)


_DEFAULT = Options()


def read_journal(lines: Iterable[str | None], options: Options = _DEFAULT) -> Export:
    """`None` stands for a line too long to be read (see `bounded_lines`)."""
    reader, skipped, last = _Reader(options), 0, 0
    for number, text in enumerate(lines, start=1):
        if text is not None and not text.strip():
            continue
        parsed = _entry(text)
        if parsed is None:
            skipped += 1
            continue
        item, last = parsed
        reader.step(item, last, number)
    reader.finish("no_response", last)  # a journal cut short
    spans = tuple(sorted(reader.spans, key=lambda s: s.start_ns))
    return Export(spans=spans, skipped=skipped, unmatched=reader.unmatched,
                  dropped=reader.dropped, lost=reader.lost,
                  invalid_traceparents=reader.invalid_traceparents)


def bounded_lines(handle: Any, limit: int = MAX_LINE) -> Iterable[str | None]:
    """The lines of a text file, without reading a long one whole: a line
    longer than `limit` is read in pieces, dropped, and given as None."""
    while True:
        line = handle.readline(limit + 1)
        if not line:
            return
        if len(line) <= limit:
            yield line
            continue
        while line and not line.endswith("\n"):
            line = handle.readline(limit)
        yield None
