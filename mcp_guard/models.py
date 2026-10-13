"""Core data models: risk levels, findings and MCP input entries."""

from __future__ import annotations

from enum import IntEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Risk(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    @classmethod
    def parse(cls, value: Any) -> Risk:
        if isinstance(value, cls):
            return value
        if isinstance(value, str) and value.upper() in cls.__members__:
            return cls[value.upper()]
        raise ValueError(f"unknown risk level {value!r} (use LOW, MEDIUM, HIGH, CRITICAL)")


class ConfigFormatError(ValueError):
    """The input cannot be read as an MCP configuration or tools list."""


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: str
    risk: Risk
    evidence: str


class AuditEntry(BaseModel):
    """One audited item. `server` is set for tools discovered live, so the
    report can say which server exposes them."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["server", "tool"]
    name: str
    findings: tuple[Finding, ...]
    server: str | None = None

    @property
    def risk(self) -> Risk:
        return max((f.risk for f in self.findings), default=Risk.LOW)

    @property
    def label(self) -> str:
        return f"{self.server} > {self.name}" if self.server else self.name


def _none_to_default(value: Any, default: Any) -> Any:
    return default if value is None else value


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)

    @field_validator("description", mode="before")
    @classmethod
    def _description(cls, value: Any) -> Any:
        return _none_to_default(value, "")

    @field_validator("inputSchema", mode="before")
    @classmethod
    def _schema(cls, value: Any) -> Any:
        return _none_to_default(value, {})


class ServerSpec(BaseModel):
    """A server entry. Accepts the variants used by Claude Desktop, Cursor,
    VS Code, Windsurf (`serverUrl`), Zed (nested `command` object) and
    Continue (`type`)."""

    model_config = ConfigDict(extra="allow")

    command: str = ""
    args: list[Any] = Field(default_factory=list)
    env: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, Any] = Field(default_factory=dict)
    url: str = ""

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        if not normalized.get("url") and normalized.get("serverUrl"):
            normalized["url"] = normalized["serverUrl"]
        nested = normalized.get("command")
        if isinstance(nested, dict):  # Zed: {"command": {"path", "args", "env"}}
            path = nested.get("path")
            # no `path`: keep the dict so validation reports a malformed entry
            normalized["command"] = path if isinstance(path, str) else nested
            for key in ("args", "env"):
                if normalized.get(key) is None:
                    normalized[key] = nested.get(key)
        return normalized

    @field_validator("command", "url", mode="before")
    @classmethod
    def _text(cls, value: Any) -> Any:
        return _none_to_default(value, "")

    @field_validator("args", mode="before")
    @classmethod
    def _args(cls, value: Any) -> Any:
        return [value] if isinstance(value, str) else _none_to_default(value, [])

    @field_validator("env", "headers", mode="before")
    @classmethod
    def _mapping(cls, value: Any) -> Any:
        return _none_to_default(value, {})
