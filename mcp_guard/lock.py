"""Rug-pull detection: fingerprint servers and tools, then compare.

`mcp-guard lock` records SHA-256 fingerprints in `mcp-guard.lock`:

- per tool: its description, its input schema, and every other field the
  server sends (title, annotations, outputSchema...);
- per server: its launch spec (command, arguments with secrets redacted,
  URL without query, env/header names) and, separately, a salted HMAC of
  the env/header values and URL parameters that do not look like secrets.

A later `inspect --lock` reports what changed. Secrets are never stored,
not even hashed, so rotating an API key does not raise an alert.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import __version__
from .analysis import sort_entries, with_findings
from .collector import Outcome, from_discovered
from .formats import Discovered
from .models import AuditEntry, ConfigFormatError, Finding, Risk, ServerSpec
from .redact import is_secret_key, redact_args, safe_url, strip_url_credentials
from .rules import RuleSet
from .snapshot import MCPSnapshot, ToolSnapshot
from .text import printable

LOCK_VERSION = 1
DEFAULT_LOCK = "mcp-guard.lock"
_PREVIEW = 80

Mode = Literal["static", "live"]


class ToolPrint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    server: str | None = None
    name: str
    occurrence: int = Field(default=0, ge=0)  # 2nd tool with the same name -> 1
    description: str
    input_schema: str
    metadata: str  # every other field: title, annotations, outputSchema...
    preview: str = ""

    @property
    def key(self) -> tuple[str | None, str, int]:
        return (self.server, self.name, self.occurrence)

    @property
    def label(self) -> str:
        return f"{self.server} > {self.name}" if self.server else self.name


class ServerPrint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    launch: str
    settings: str


class LockFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = LOCK_VERSION
    generator: str = f"mcp-guard {__version__}"
    created: str = ""
    mode: Mode = "static"
    salt: str = Field(default_factory=lambda: secrets.token_hex(16), pattern=r"^[0-9a-f]{32}$")
    servers: dict[str, ServerPrint] = Field(default_factory=dict)
    tools: list[ToolPrint] = Field(default_factory=list)


# --- fingerprints ---------------------------------------------------------------


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _non_secret(pairs: list[tuple[str, Any]]) -> list[tuple[str, str]]:
    return sorted((str(k), strip_url_credentials(str(v)))
                  for k, v in pairs if not is_secret_key(str(k)))


def server_print(server: ServerSpec, salt: str) -> ServerPrint:
    query = parse_qsl(urlsplit(server.url).query) if server.url else []
    settings = {"env": _non_secret(list(server.env.items())),
                "headers": _non_secret(list(server.headers.items())),
                "query": _non_secret(list(query))}
    return ServerPrint(
        launch=_sha256({
            "command": server.command,
            "args": redact_args([str(a) for a in server.args]),
            "url": safe_url(server.url) if server.url else "",
            "env": sorted(map(str, server.env)),
            "headers": sorted(map(str, server.headers)),
        }),
        settings=hmac.new(bytes.fromhex(salt), _canonical(settings), hashlib.sha256).hexdigest(),
    )


def tool_print(tool: ToolSnapshot, server: str | None = None, occurrence: int = 0,
               ) -> ToolPrint:
    others = {k: v for k, v in tool.to_mcp().items()
              if k not in ("name", "description", "inputSchema")}
    return ToolPrint(server=server, name=tool.name, occurrence=occurrence,
                     description=_sha256(tool.description),
                     input_schema=_sha256(tool.input_schema), metadata=_sha256(others),
                     preview=printable(tool.description, _PREVIEW))


def _tool_prints(tools: tuple[ToolSnapshot, ...], server: str | None) -> list[ToolPrint]:
    prints: list[ToolPrint] = []
    seen: dict[str, int] = {}
    for tool in tools:
        if tool.parse_error is not None:
            continue  # reported as malformed-entry by the audit
        prints.append(tool_print(tool, server, seen.get(tool.name, 0)))
        seen[tool.name] = seen.get(tool.name, 0) + 1
    return prints


def fingerprint(snap: MCPSnapshot, salt: str | None = None) -> LockFile:
    """Fingerprints of a snapshot. Pass the locked `salt` when the result is
    meant to be compared with a lock."""
    lock = LockFile(mode=snap.mode,
                    created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    salt=salt or secrets.token_hex(16))
    for server in snap.servers:
        if server.spec is not None:
            lock.servers[server.name] = server_print(server.spec, lock.salt)
    lock.tools += _tool_prints(snap.tools, None)
    for server in snap.servers:
        if server.live_status == "captured":
            lock.tools += _tool_prints(server.tools, server.name)
    return lock


def snapshot(found: Discovered, live: dict[str, Outcome] | None = None,
             salt: str | None = None) -> LockFile:
    """Fingerprints of the config (and of live tools, if given). `live` maps a
    server name to its tool list, or to an exception if it failed."""
    return fingerprint(from_discovered(found, captures=live), salt)


# --- file I/O -------------------------------------------------------------------


def write_lock(lock: LockFile, path: Path) -> None:
    path.write_text(lock.model_dump_json(indent=2) + "\n", encoding="utf-8")


def read_lock(path: Path) -> LockFile:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigFormatError(f"Cannot read lock file {path}: {exc}") from exc
    if isinstance(data, dict) and data.get("version") != LOCK_VERSION:
        raise ConfigFormatError(
            f"{path} has lock version {data.get('version')!r}; this mcp-guard reads "
            f"version {LOCK_VERSION}. Regenerate it with `mcp-guard lock`.")
    try:
        return LockFile.model_validate(data)
    except ValidationError as exc:
        raise ConfigFormatError(f"Invalid lock file {path}:\n{exc}") from exc


# --- comparison -----------------------------------------------------------------

Changes = dict[tuple[str, str], tuple[Finding, ...]]


def _add(changes: Changes, key: tuple[str, str], finding: Finding) -> None:
    changes[key] = changes.get(key, ()) + (finding,)


def _tool_change(old: ToolPrint, new: ToolPrint) -> Finding | None:
    parts = (("description", old.description, new.description),
             ("input schema", old.input_schema, new.input_schema),
             ("metadata (title, annotations, output schema...)", old.metadata, new.metadata))
    changed = [part for part, a, b in parts if a != b]
    if not changed:
        return None
    was = (f"; locked description began: '{printable(old.preview, _PREVIEW)}'"
           if "description" in changed else "")
    return Finding(category="tool-changed", risk=Risk.HIGH,
                   evidence=" and ".join(changed) + " changed" + was)


def _server_changes(locked: LockFile, current: LockFile, changes: Changes) -> None:
    for name in current.servers.keys() - locked.servers.keys():
        _add(changes, ("server", name), Finding(category="server-added", risk=Risk.MEDIUM,
                                                evidence="not in the lock file"))
    for name in locked.servers.keys() - current.servers.keys():
        _add(changes, ("server", name), Finding(
            category="server-removed", risk=Risk.LOW,
            evidence="in the lock file but no longer present"))
    for name in locked.servers.keys() & current.servers.keys():
        old, new = locked.servers[name], current.servers[name]
        parts = [part for part, changed in (
            ("command, arguments, URL or env/header names", old.launch != new.launch),
            ("env/header values or URL parameters", old.settings != new.settings)) if changed]
        if parts:
            _add(changes, ("server", name), Finding(
                category="server-changed", risk=Risk.HIGH,
                evidence=" and ".join(parts) + " changed"))


def _tool_changes(locked: LockFile, current: LockFile, unreachable: set[str],
                  changes: Changes) -> list[ToolPrint]:
    """Record tool differences; return the removed tools (no entry to attach to)."""
    old = {t.key: t for t in locked.tools}
    new = {t.key: t for t in current.tools}
    for key in new.keys() - old.keys():
        _add(changes, ("tool", new[key].label), Finding(
            category="tool-added", risk=Risk.MEDIUM, evidence="not in the lock file"))
    for key in old.keys() & new.keys():
        change = _tool_change(old[key], new[key])
        if change:
            _add(changes, ("tool", new[key].label), change)
    return [old[key] for key in old.keys() - new.keys()
            if old[key].server not in unreachable]


def compare(locked: LockFile, current: LockFile, entries: tuple[AuditEntry, ...],
            ruleset: RuleSet, unreachable: set[str] | None = None,
            ) -> tuple[AuditEntry, ...]:
    """Merge lock differences into the audit. Tools of servers that could not
    be reached are not reported as removed (they get live-discovery-failed).
    `current` must be built with the locked salt."""
    if locked.mode != current.mode:
        hint = "add --live" if locked.mode == "live" else "drop --live"
        raise ConfigFormatError(
            f"the lock file was created in {locked.mode} mode; {hint} to compare")
    changes: Changes = {}
    _server_changes(locked, current, changes)
    removed = _tool_changes(locked, current, unreachable or set(), changes)
    existing = {(e.kind, e.label) for e in entries}
    merged = list(with_findings(entries, changes, ruleset))
    for (kind, name), findings in changes.items():
        if kind == "server" and (kind, name) not in existing:  # removed server
            merged.append(AuditEntry(kind="server", name=name, findings=ruleset.keep(findings)))
    for tool in removed:
        merged.append(AuditEntry(kind="tool", name=tool.name, server=tool.server,
                                 findings=ruleset.keep((Finding(
                                     category="tool-removed", risk=Risk.LOW,
                                     evidence="in the lock file but no longer present"),))))
    return sort_entries(merged, ruleset)
