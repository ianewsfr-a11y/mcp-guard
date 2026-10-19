"""Spans as an OTLP/JSON trace export (ExportTraceServiceRequest).

Follows the OTLP JSON encoding: trace and span ids in lower-case hex, 64-bit
integers and nanosecond times as decimal strings, enums as integers. The
spans are of kind INTERNAL: the proxy observes the exchange between a client
and a server, it is neither. Their names and attributes follow the
OpenTelemetry semantic conventions for MCP, still in development.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .. import __version__
from .journal import Span

SPAN_KIND_INTERNAL = 1
STATUS_CODE_ERROR = 2
SEMCONV = "OpenTelemetry semantic conventions for MCP (status: development)"


def _value(value: str | int) -> dict[str, str]:
    if isinstance(value, int):
        return {"intValue": str(value)}
    return {"stringValue": value}


def _attributes(pairs: Iterable[tuple[str, str | int]]) -> list[dict[str, Any]]:
    return [{"key": key, "value": _value(value)} for key, value in pairs]


def _span(span: Span) -> dict[str, Any]:
    data: dict[str, Any] = {
        "traceId": span.trace_id, "spanId": span.span_id, "name": span.name,
        "kind": SPAN_KIND_INTERNAL, "startTimeUnixNano": str(span.start_ns),
        "endTimeUnixNano": str(span.end_ns), "attributes": _attributes(span.attributes),
        "status": {"code": STATUS_CODE_ERROR} if span.error else {}}
    if span.parent_id:
        data["parentSpanId"] = span.parent_id
    return data


def to_otlp(spans: Iterable[Span]) -> dict[str, Any]:
    return {"resourceSpans": [{
        "resource": {"attributes": _attributes([("service.name", "mcp-guard proxy")])},
        "scopeSpans": [{
            "scope": {"name": "mcp-guard", "version": __version__,
                      "attributes": _attributes([("mcp_guard.semconv", SEMCONV)])},
            "spans": [_span(span) for span in spans]}]}]}
