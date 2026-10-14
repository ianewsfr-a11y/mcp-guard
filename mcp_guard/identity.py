"""Who a server says it is: its `serverInfo` (name, version), the protocol
version it speaks and a hash of its capabilities.

Where it comes from depends on the MCP revision:

- up to 2025-11-25, the result of `initialize`;
- from 2026-07-28, the result of `server/discover`, which announces the
  supported protocol versions, the capabilities and the server identity
  (there is no `initialize` handshake any more), and the `_meta` of any
  result, under `io.modelcontextprotocol/serverInfo`.

Source for the 2026-07-28 behavior: the MCP specification changelog for that
revision (major changes, point 3), as relayed by the project owner; it could
not be checked from here. `server/discover` carries no tools: `tools/list`
stays the only source for them.

A change of identity or capabilities is reported as `identity-changed`
MEDIUM, a category of its own (`server-changed` is HIGH, for a changed
command, arguments or URL): an upgrade is legitimate, but it is exactly when
a rug pull would happen.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .models import Finding, Risk
from .text import printable

META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
CATEGORY = "identity-changed"
_MAX_TEXT = 200


class ServerIdentity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str | None = Field(default=None, max_length=_MAX_TEXT)
    version: str | None = Field(default=None, max_length=_MAX_TEXT)
    protocol: str | None = Field(default=None, max_length=_MAX_TEXT)
    capabilities: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")  # sha256


def _text(value: Any) -> str | None:
    return printable(str(value), _MAX_TEXT) if isinstance(value, (str, int, float)) else None


def _hash(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _protocol(result: dict[str, Any]) -> str | None:
    if "protocolVersion" in result:
        return _text(result.get("protocolVersion"))
    versions = result.get("supportedVersions", result.get("protocolVersions"))
    if isinstance(versions, list) and versions:
        return _text(",".join(map(str, versions)))
    return None


def identity_from(result: Any) -> ServerIdentity | None:
    """The identity declared in a result (`initialize`, `server/discover`, or
    any result whose `_meta` carries `serverInfo`); None when there is none."""
    if not isinstance(result, dict):
        return None
    meta = result.get("_meta")
    info = result.get("serverInfo")
    if not isinstance(info, dict) and isinstance(meta, dict):
        info = meta.get(META_SERVER_INFO)
    capabilities = result.get("capabilities")
    if not isinstance(info, dict) and not isinstance(capabilities, dict):
        return None
    info = info if isinstance(info, dict) else {}
    return ServerIdentity(
        name=_text(info.get("name")), version=_text(info.get("version")),
        protocol=_protocol(result),
        capabilities=_hash(capabilities) if isinstance(capabilities, dict) else None)


def merged(old: ServerIdentity | None, new: ServerIdentity | None) -> ServerIdentity | None:
    """`new` completed by `old`: a `_meta` serverInfo has no capabilities."""
    if old is None or new is None:
        return new or old
    return ServerIdentity(**{k: getattr(new, k) or getattr(old, k)
                             for k in ServerIdentity.model_fields})


def identity_changes(old: ServerIdentity, new: ServerIdentity) -> list[str]:
    """What changed, comparing only what both sides declare. The protocol
    version is recorded but not compared: the client negotiates it, so a
    different client legitimately gets another one."""
    changes = []
    for field in ("name", "version"):
        before, after = getattr(old, field), getattr(new, field)
        if before is not None and after is not None and before != after:
            changes.append(f"{field} {before!r} -> {after!r}")
    if old.capabilities and new.capabilities and old.capabilities != new.capabilities:
        changes.append("capabilities changed")
    return changes


def identity_findings(old: ServerIdentity, new: ServerIdentity, where: str) -> list[Finding]:
    changes = identity_changes(old, new)
    if not changes:
        return []
    return [Finding(category=CATEGORY, risk=Risk.MEDIUM,
                    evidence=f"server identity changed {where}: " + "; ".join(changes))]
