"""Core data models: risk levels, findings and MCP input entries."""

from __future__ import annotations

import hashlib
from enum import IntEnum
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .text import redact_urls


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
    """`id` is filled in when the finding is attached to an AuditEntry: it is
    stable across runs and machines for the same issue on the same item.

    `field` names what the finding is about within its item (`env:API_KEY`,
    `url`, `description`...): with the category and the item, it makes the
    id, never the evidence. Every URL in the evidence is reduced to its
    scheme and host, whoever builds the finding."""

    model_config = ConfigDict(frozen=True)

    category: str
    risk: Risk
    evidence: str
    field: str = ""
    id: str = ""

    @field_validator("evidence")
    @classmethod
    def _no_url_details(cls, value: str) -> str:
        return redact_urls(value)


def label_of(name: str, server: str | None) -> str:
    return f"{server} > {name}" if server else name


def finding_id(kind: str, label: str, finding: Finding, occurrence: int = 1) -> str:
    """32 hex chars of SHA-256 over rule, item (kind and label: server and
    tool) and field, not the evidence: a finding keeps its id when its
    evidence is reworded or redacted. The same value is the SARIF partial
    fingerprint. The n-th finding of an item with the same rule and field
    (n > 1) adds n, so ids stay distinct within an item. Two identical
    findings on two tools with the same name and server share an id."""
    identity = f"mcp-guard/{finding.category}|{kind}|{label}|{finding.field}"
    if occurrence > 1:
        identity += f"|{occurrence}"
    return hashlib.sha256(identity.encode()).hexdigest()[:32]


def _with_ids(findings: tuple[Any, ...], kind: Any, label: Any) -> tuple[Any, ...]:
    seen: dict[tuple[str, str], int] = {}
    result = []
    for finding in findings:
        if isinstance(finding, Finding) and not finding.id:
            key = (finding.category, finding.field)
            seen[key] = seen.get(key, 0) + 1
            finding = finding.model_copy(update={"id": finding_id(
                str(kind), str(label), finding, seen[key])})
        result.append(finding)
    return tuple(result)


class AuditEntry(BaseModel):
    """One audited item. `server` is set for tools discovered live, so the
    report can say which server exposes them.

    Finding ids are set during validation: build a new AuditEntry to change
    its findings or name, never `model_copy(update=...)`, which skips it."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["server", "tool", "config"]  # config: a rule on all servers at once
    name: str
    findings: tuple[Finding, ...]
    server: str | None = None

    @model_validator(mode="after")
    def _stable_ids(self) -> AuditEntry:
        if all(f.id for f in self.findings):
            return self
        findings = _with_ids(self.findings, self.kind, self.label)
        # frozen model: bypass __setattr__ once, during validation only
        object.__setattr__(self, "findings", findings)
        return self

    @property
    def risk(self) -> Risk:
        return max((f.risk for f in self.findings), default=Risk.LOW)

    @property
    def label(self) -> str:
        return label_of(self.name, self.server)


def error_fields(error: ValidationError) -> str:
    """The fields a validation error is about, e.g. `args, env.KEY`."""
    return ", ".join(sorted({".".join(map(str, e["loc"])) or "entry" for e in error.errors()}))


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
