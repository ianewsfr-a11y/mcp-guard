"""Versioned snapshot: the state of an MCP setup captured at one point in time.

`collector` builds an `MCPSnapshot` from a config file (and, with `--live`,
from what each server answers); `analyzer` turns it into findings; the lock
file and the TUI read it. Nothing downstream looks at raw config data.

Serialization is canonical (sorted keys, compact separators, UTF-8) and
never contains a literal secret: server specs are stored redacted (see
`redact.stored_spec`). `canonical_json()` and `digest` leave out when, from
which path and by which mcp-guard version the snapshot was taken, so two
captures of an unchanged setup have the same digest. JSON is ASCII-escaped,
so any string a server sends (even a lone surrogate) serializes.

A snapshot read back with `from_json` holds redacted specs: re-analyzing it
reports secrets with different evidence (and ids) than the original capture.
Analyze the capture itself; store the findings if you need them later.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from . import __version__
from .models import ServerSpec, ToolSpec, label_of
from .redact import stored_spec

SNAPSHOT_VERSION: Literal[1] = 1
_VOLATILE = frozenset({"captured_at", "generator", "source"})

Origin = Literal["config", "live"]
LiveStatus = Literal["not-contacted", "captured", "failed"]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Provenance(_Frozen):
    """Where an item comes from: the config file, or a live server answer.
    `path` locates it, e.g. `tools[2]`, `mcpServers.github`, `tools/list[0]`."""

    origin: Origin
    path: str
    server: str | None = None


class ToolSnapshot(_Frozen):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)  # title, outputSchema...
    provenance: Provenance
    parse_error: str | None = None  # fields that failed validation

    @property
    def server(self) -> str | None:
        return self.provenance.server

    @property
    def label(self) -> str:
        return label_of(self.name, self.server)

    def to_mcp(self) -> dict[str, Any]:
        """The tool as an MCP server sends it (`tools/list` item)."""
        tool: dict[str, Any] = {**self.metadata, "name": self.name,
                                "description": self.description,
                                "inputSchema": self.input_schema}
        if self.annotations is not None:
            tool["annotations"] = self.annotations
        return tool

    def spec(self) -> ToolSpec:
        return ToolSpec.model_validate(self.to_mcp())


class ResourceSnapshot(_Frozen):
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance


class PromptSnapshot(_Frozen):
    name: str
    description: str = ""
    arguments: tuple[dict[str, Any], ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance


class ServerSnapshot(_Frozen):
    name: str
    spec: ServerSpec | None = None  # None when the entry could not be parsed
    parse_error: str | None = None
    provenance: Provenance
    live_status: LiveStatus = "not-contacted"
    live_error: str | None = None
    tools: tuple[ToolSnapshot, ...] = ()
    resources: tuple[ResourceSnapshot, ...] = ()
    prompts: tuple[PromptSnapshot, ...] = ()
    capture_warnings: tuple[str, ...] = ()

    @field_serializer("spec")
    def _redacted(self, spec: ServerSpec | None) -> dict[str, Any] | None:
        return stored_spec(spec) if spec is not None else None

    @property
    def disabled(self) -> bool:
        return self.spec is not None and (self.spec.model_extra or {}).get("disabled") is True


class MCPSnapshot(_Frozen):
    schema_version: Literal[1] = SNAPSHOT_VERSION
    generator: str = f"mcp-guard {__version__}"
    captured_at: str = ""
    source: str = ""
    format: str = ""
    mode: Literal["static", "live"] = "static"
    servers: tuple[ServerSnapshot, ...] = ()
    tools: tuple[ToolSnapshot, ...] = ()  # listed in the file itself, not by a server

    def server(self, name: str) -> ServerSnapshot | None:
        return next((s for s in self.servers if s.name == name), None)

    def all_tools(self) -> Iterator[ToolSnapshot]:
        """Tools from the file, then each server's live tools, in order."""
        yield from self.tools
        for server in self.servers:
            yield from server.tools

    def canonical_json(self) -> str:
        """Stable serialization of the content (no timestamp, path or generator)."""
        return _dumps(self.model_dump(mode="json", exclude=set(_VOLATILE)))

    @property
    def digest(self) -> str:
        """SHA-256 of `canonical_json()`: the version id of this capture."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def to_json(self) -> str:
        """Everything, including the volatile fields, with sorted keys."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, indent=2)

    @classmethod
    def from_json(cls, text: str) -> MCPSnapshot:
        return cls.model_validate_json(text)


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
