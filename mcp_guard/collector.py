"""Collection: config file (and, with --live, server answers) -> MCPSnapshot.

This is the only layer that reads raw config data or live results. It
validates every entry once; entries that cannot be parsed are kept, with
`parse_error`, so the analyzer can report them as malformed.

Starting servers is opt-in: `launch_plan` says what would run, the caller
asks the user, then `capture_live` runs it.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, TypeAlias

from pydantic import ValidationError

from .formats import Discovered, discover
from .identity import identity_from
from .live import Capture, Fetcher, LiveError, LiveResults, capture_server, fetch_all
from .models import ServerSpec, ToolSpec, error_fields
from .snapshot import (
    MCPSnapshot,
    Origin,
    PromptSnapshot,
    Provenance,
    ResourceSnapshot,
    ServerSnapshot,
    ToolSnapshot,
)

# per server: a full Capture, its tools only, or why it could not be reached
Outcome: TypeAlias = "Capture | list[Any] | LiveError"
_TOOL_FIELDS = ("name", "description", "inputSchema")
MAX_WARNINGS = 20


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- items ----------------------------------------------------------------------


def tool_snapshot(raw: Any, index: int, origin: Origin = "config",
                  server: str | None = None) -> ToolSnapshot:
    prefix = "tools" if origin == "config" else "tools/list"
    provenance = Provenance(origin=origin, path=f"{prefix}[{index}]", server=server)
    try:
        spec = ToolSpec.model_validate(raw)
    except ValidationError as exc:
        fallback = raw.get("name") if isinstance(raw, dict) else None
        return ToolSnapshot(name=str(fallback or f"tools[{index}]"), provenance=provenance,
                            parse_error=error_fields(exc))
    others = {k: v for k, v in spec.model_dump().items() if k not in _TOOL_FIELDS}
    annotations = others.get("annotations")
    if isinstance(annotations, dict):  # anything else stays in metadata, as sent
        others = {k: v for k, v in others.items() if k != "annotations"}
    return ToolSnapshot(name=spec.name, description=spec.description,
                        input_schema=spec.inputSchema,
                        annotations=annotations if isinstance(annotations, dict) else None,
                        metadata=others, provenance=provenance)


def _text(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    return value if isinstance(value, str) else ""


def _resource(raw: Any, index: int, server: str) -> ResourceSnapshot | str:
    path = f"resources/list[{index}]"
    if not isinstance(raw, dict) or not isinstance(raw.get("uri"), str):
        return f"{path}: no `uri`, not recorded"
    mime = raw.get("mimeType")
    return ResourceSnapshot(
        uri=raw["uri"], name=_text(raw, "name"), description=_text(raw, "description"),
        mime_type=mime if isinstance(mime, str) else None,
        metadata={k: v for k, v in raw.items()
                  if k not in ("uri", "name", "description", "mimeType")},
        provenance=Provenance(origin="live", path=path, server=server))


def _prompt(raw: Any, index: int, server: str) -> PromptSnapshot | str:
    path = f"prompts/list[{index}]"
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
        return f"{path}: no `name`, not recorded"
    arguments = raw.get("arguments")
    return PromptSnapshot(
        name=raw["name"], description=_text(raw, "description"),
        arguments=tuple(a for a in arguments if isinstance(a, dict))
        if isinstance(arguments, list) else (),
        metadata={k: v for k, v in raw.items() if k not in ("name", "description", "arguments")},
        provenance=Provenance(origin="live", path=path, server=server))


# --- servers --------------------------------------------------------------------


def _captured(base: ServerSnapshot, outcome: Outcome) -> ServerSnapshot:
    if isinstance(outcome, Exception):  # LiveError, or any failure a fetcher reports
        return base.model_copy(update={"live_status": "failed", "live_error": str(outcome)})
    capture = outcome if isinstance(outcome, Capture) else Capture(tuple(outcome))
    name = base.name
    resources = [_resource(r, i, name) for i, r in enumerate(capture.resources)]
    prompts = [_prompt(p, i, name) for i, p in enumerate(capture.prompts)]
    skipped = [item for item in (*resources, *prompts) if isinstance(item, str)]
    warnings = [*capture.warnings, *skipped]
    if len(warnings) > MAX_WARNINGS:
        warnings = warnings[:MAX_WARNINGS] + [f"... and {len(warnings) - MAX_WARNINGS} more"]
    return base.model_copy(update={
        "live_status": "captured",
        "tools": tuple(tool_snapshot(t, i, "live", name) for i, t in enumerate(capture.tools)),
        "resources": tuple(r for r in resources if isinstance(r, ResourceSnapshot)),
        "prompts": tuple(p for p in prompts if isinstance(p, PromptSnapshot)),
        "capture_warnings": tuple(warnings),
        "instructions": capture.instructions,
        "identity": identity_from(capture.identity),
    })


def server_snapshot(name: str, raw: Any, outcome: Outcome | None = None) -> ServerSnapshot:
    provenance = Provenance(origin="config", path=name)
    try:
        spec = ServerSpec.model_validate(raw)
    except ValidationError as exc:
        return ServerSnapshot(name=name, provenance=provenance, parse_error=error_fields(exc))
    base = ServerSnapshot(name=name, spec=spec, provenance=provenance)
    return base if outcome is None else _captured(base, outcome)


# --- whole config ---------------------------------------------------------------


def from_discovered(found: Discovered, source: str = "",
                    captures: Mapping[str, Outcome] | None = None,
                    captured_at: str | None = None) -> MCPSnapshot:
    """`captures` (live mode) maps a server name to what it answered, or to the
    error that prevented it; `None` means static mode."""
    unknown = set(captures or {}) - set(found.servers)
    if unknown:
        raise ValueError(f"live results for servers not in the config: {sorted(unknown)}")
    outcomes = captures or {}
    return MCPSnapshot(
        captured_at=captured_at or _now(), source=source, format=found.format,
        mode="live" if captures is not None else "static",
        servers=tuple(server_snapshot(name, raw, outcomes.get(name))
                      for name, raw in found.servers.items()),
        tools=tuple(tool_snapshot(raw, i) for i, raw in enumerate(found.tools)))


def collect(data: Any, source: str = "", captures: Mapping[str, Outcome] | None = None,
            captured_at: str | None = None) -> MCPSnapshot:
    """Snapshot of a loaded config. Raises ConfigFormatError if it holds no
    MCP servers or tools list."""
    return from_discovered(discover(data), source, captures, captured_at)


# --- live -----------------------------------------------------------------------


def launch_plan(snapshot: MCPSnapshot) -> list[tuple[str, ServerSpec]]:
    """Servers `--live` would start or contact: parsed and not disabled."""
    return [(s.name, s.spec) for s in snapshot.servers
            if s.spec is not None and not s.disabled]


def capture_live(plan: list[tuple[str, ServerSpec]], timeout: float,
                 fetch: Fetcher = capture_server) -> LiveResults:
    """Run the plan: one Capture (or LiveError) per server."""
    return fetch_all(plan, timeout, fetch)
