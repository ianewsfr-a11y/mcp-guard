"""Rug-pull detection: fingerprint servers and tools, then compare.

`mcp-guard lock` records SHA-256 fingerprints in `mcp-guard.lock`:

- per tool: its description, its input schema, and every other field the
  server sends (title, annotations, outputSchema...);
- per server: its launch spec (command, arguments with secrets redacted,
  URL without query, env/header names) and, separately, a salted HMAC of
  the env/header values and URL parameters that do not look like secrets.

A later `inspect --lock` reports what changed. Secrets are never stored,
not even hashed, so rotating an API key does not raise an alert.

Version 2 (v0.7) also keeps, per tool, the values of the four MCP security
hints (readOnlyHint, destructiveHint, idempotentHint, openWorldHint: booleans,
not secrets), a separate hash of the annotations, and a hash of the
description's "skeleton" (invisible characters removed, look-alike letters
mapped), so a change made only of such characters is named as such.
Severities: description, annotations or input schema HIGH, other metadata
MEDIUM, added tool MEDIUM, removed tool LOW. Version 1 locks are still read;
regenerate them to get the per-annotation detail.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from . import __version__
from .analysis import sort_entries, with_findings
from .analyzer import analyze
from .annotations import CATEGORY as CONTRADICTION
from .annotations import NON_BOOLEAN, SECURITY_HINTS, security_hints
from .collector import Outcome, from_discovered
from .formats import Discovered
from .identity import ServerIdentity, identity_findings
from .models import AuditEntry, ConfigFormatError, Finding, Risk, ServerSpec
from .pin import Pin, compute_pin
from .poisoning import look_alikes, normalize
from .redact import is_secret_key, redact_args, safe_url, strip_url_credentials
from .rules import RuleSet
from .snapshot import MCPSnapshot, ToolSnapshot
from .text import escaped, printable

LOCK_VERSION = 2
READABLE_VERSIONS = (1, 2)
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
    metadata: str  # every other field (title, outputSchema...); v1: annotations too
    preview: str = Field(default="", max_length=4 * _PREVIEW)
    annotations: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")  # v2 hash
    hints: dict[str, bool | str | None] | None = None  # v2: security hint values
    skeleton: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")  # v2 hash

    @field_validator("hints")
    @classmethod
    def _known_hints(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        unknown = sorted(set(value) - set(SECURITY_HINTS))
        if unknown:
            raise ValueError(f"unknown security hints: {unknown}")
        if any(isinstance(v, str) and v != NON_BOOLEAN for v in value.values()):
            raise ValueError(f"hint values must be true, false, null or {NON_BOOLEAN!r}")
        return value

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
    identity: ServerIdentity | None = None  # live locks: serverInfo, capabilities
    pin: Pin | None = None  # stdio servers: what exactly runs (`lock` computes it)


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


# Cache hints (MCP 2026-07-28) change with no change of meaning: never hashed.
_UNHASHED = frozenset({"name", "description", "inputSchema", "ttlMs", "cacheScope"})


def tool_print(tool: ToolSnapshot, server: str | None = None, occurrence: int = 0,
               version: int = LOCK_VERSION) -> ToolPrint:
    others = {k: v for k, v in tool.to_mcp().items() if k not in _UNHASHED}
    base = ToolPrint(server=server, name=tool.name, occurrence=occurrence,
                     description=_sha256(tool.description),
                     input_schema=_sha256(tool.input_schema), metadata=_sha256(others),
                     preview=printable(tool.description, _PREVIEW))
    if version == 1:  # metadata includes the annotations, as in v0.4-v0.6 locks
        return base
    present = "annotations" in others
    annotations = others.pop("annotations", None)
    return base.model_copy(update={
        "metadata": _sha256(others),
        "annotations": _sha256({"present": present, "value": annotations}),
        "hints": security_hints(annotations),
        "skeleton": _sha256(normalize(tool.description))})


def _tool_prints(tools: tuple[ToolSnapshot, ...], server: str | None,
                 version: int = LOCK_VERSION) -> list[ToolPrint]:
    prints: list[ToolPrint] = []
    seen: dict[str, int] = {}
    for tool in tools:
        if tool.parse_error is not None:
            continue  # reported as malformed-entry by the audit
        prints.append(tool_print(tool, server, seen.get(tool.name, 0), version))
        seen[tool.name] = seen.get(tool.name, 0) + 1
    return prints


def fingerprint(snap: MCPSnapshot, salt: str | None = None,
                version: int = LOCK_VERSION, pins: bool = False) -> LockFile:
    """Fingerprints of a snapshot. Pass the locked `salt` (and `version`) when
    the result is meant to be compared with a lock. `pins` also pins the
    command of each stdio server (what `mcp-guard lock` writes)."""
    lock = LockFile(version=version, mode=snap.mode,
                    created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    salt=salt or secrets.token_hex(16))
    for server in snap.servers:
        if server.spec is not None:
            pin = (compute_pin(server.spec.command, [str(a) for a in server.spec.args], lock.salt)
                   if pins and server.spec.command else None)
            lock.servers[server.name] = server_print(server.spec, lock.salt).model_copy(
                update={"identity": server.identity, "pin": pin})
    lock.tools += _tool_prints(snap.tools, None, version)
    for server in snap.servers:
        if server.live_status == "captured":
            lock.tools += _tool_prints(server.tools, server.name, version)
    return lock


def snapshot(found: Discovered, live: dict[str, Outcome] | None = None,
             salt: str | None = None) -> LockFile:
    """Fingerprints of the config (and of live tools, if given). `live` maps a
    server name to its tool list, or to an exception if it failed."""
    return fingerprint(from_discovered(found, captures=live), salt)


# --- file I/O -------------------------------------------------------------------


def write_lock(lock: LockFile, path: Path) -> None:
    """Servers and tools are written in a fixed order, so the same setup gives
    the same file whatever the order of servers in the config."""
    ordered = lock.model_copy(update={
        "servers": dict(sorted(lock.servers.items())),
        "tools": sorted(lock.tools, key=lambda t: (t.server is not None, t.server or "",
                                                   t.name, t.occurrence))})
    # absent optional fields are left out, as in v0.7 files
    path.write_text(ordered.model_dump_json(indent=2, exclude_none=True) + "\n",
                    encoding="utf-8")


def read_lock(path: Path) -> LockFile:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigFormatError(f"Cannot read lock file {path}: {exc}") from exc
    if isinstance(data, dict) and data.get("version") not in READABLE_VERSIONS:
        raise ConfigFormatError(
            f"{path} has lock version {data.get('version')!r}; this mcp-guard reads "
            f"versions {', '.join(map(str, READABLE_VERSIONS))}. "
            f"Regenerate it with `mcp-guard lock`.")
    try:
        return LockFile.model_validate(data)
    except ValidationError as exc:
        raise ConfigFormatError(f"Invalid lock file {path}:\n{exc}") from exc


# --- comparison -----------------------------------------------------------------

Changes = dict[tuple[str, str], tuple[Finding, ...]]
LOCK_CATEGORIES = frozenset({"tool-changed", "server-changed", "tool-added", "server-added",
                             "tool-removed", "server-removed"})


def _add(changes: Changes, key: tuple[str, str], finding: Finding) -> None:
    changes[key] = changes.get(key, ()) + (finding,)


_MISSING = object()


def _changed(risk: Risk, evidence: str) -> Finding:
    return Finding(category="tool-changed", risk=risk, evidence=evidence)


def _shown(value: Any) -> str:
    return json.dumps(value) if isinstance(value, bool) or value is None else repr(value)


def _hint_changes(old: ToolPrint, new: ToolPrint) -> list[str]:
    """`readOnlyHint: true -> false`, `destructiveHint removed (was true)`..."""
    if old.hints is None or new.hints is None:
        return []
    changes = []
    for hint in SECURITY_HINTS:
        before, after = old.hints.get(hint, _MISSING), new.hints.get(hint, _MISSING)
        if before == after and type(before) is type(after):
            continue
        if after is _MISSING:
            changes.append(f"{hint} removed (was {_shown(before)})")
        elif before is _MISSING:
            changes.append(f"{hint} added: {_shown(after)}")
        else:
            changes.append(f"{hint}: {_shown(before)} -> {_shown(after)}")
    return changes


def _hidden_characters(text: str) -> str:
    found = look_alikes(text)
    if not found:
        return ("the current text has no invisible or look-alike character, so the "
                "difference is whitespace, HTML entities, quotes, or such characters "
                "removed; it reads '" + escaped(text[:60]) + "...' (escaped)")
    names = ", ".join(f"{escaped(ch)} {unicodedata.name(ch, 'unnamed').lower()} at offset "
                      f"{offset}" for offset, ch in found[:5])
    more = f" and {len(found) - 5} more" if len(found) > 5 else ""
    first = found[0][0]
    excerpt = escaped(text[max(0, first - 30):first + 30])
    return f"the current text has {names}{more}; it reads '...{excerpt}...' (escaped)"


def _description_change(old: ToolPrint, new: ToolPrint, text: str | None) -> Finding:
    if old.skeleton and old.skeleton == new.skeleton:
        detail = _hidden_characters(text) if text is not None else "see the current text"
        return _changed(Risk.HIGH, "description changed only by invisible characters, "
                                     f"look-alike letters or formatting: {detail}")
    return _changed(Risk.HIGH, "description changed; locked description began: "
                                 f"'{printable(old.preview, _PREVIEW)}'")


def _annotation_changes(old: ToolPrint, new: ToolPrint, contradicted: bool) -> list[Finding]:
    hints = _hint_changes(old, new)
    note = ("; the tool now contradicts its own description (annotation-contradiction)"
            if contradicted else "")
    if hints:
        return [_changed(Risk.HIGH, f"annotation {change}{note}") for change in hints]
    if old.annotations is not None and new.annotations is not None \
            and old.annotations != new.annotations:
        return [_changed(Risk.HIGH, f"annotations changed (not a security hint){note}")]
    return []


def _tool_change(old: ToolPrint, new: ToolPrint, text: str | None = None,
                 contradicted: bool = False) -> list[Finding]:
    """One finding per kind of change, each with its own severity."""
    findings = []
    if old.description != new.description:
        findings.append(_description_change(old, new, text))
    if old.input_schema != new.input_schema:
        findings.append(_changed(Risk.HIGH, "input schema changed"))
    findings += _annotation_changes(old, new, contradicted)
    if old.metadata != new.metadata:
        findings.append(
            _changed(Risk.MEDIUM, "metadata changed (title, output schema...)")
            if old.annotations is not None else
            _changed(Risk.HIGH, "metadata (title, annotations, output schema...) changed; "
                                "regenerate the lock (version 2) to see which annotation"))
    return findings


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
        if old.identity is not None and new.identity is not None:
            for finding in identity_findings(old.identity, new.identity, "since the lock"):
                _add(changes, ("server", name), finding)


def _tool_changes(locked: LockFile, current: LockFile, unreachable: set[str],
                  changes: Changes, context: _Context) -> list[ToolPrint]:
    """Record tool differences; return the removed tools (no entry to attach to)."""
    old = {t.key: t for t in locked.tools}
    new = {t.key: t for t in current.tools}
    for key in new.keys() - old.keys():
        _add(changes, ("tool", new[key].label), Finding(
            category="tool-added", risk=Risk.MEDIUM, evidence="not in the lock file"))
    for key in old.keys() & new.keys():
        label = new[key].label
        for change in _tool_change(old[key], new[key], context.texts.get(key),
                                   label in context.contradicted):
            _add(changes, ("tool", label), change)
    return [old[key] for key in old.keys() - new.keys()
            if old[key].server not in unreachable]


class _Context:
    """What the comparison needs from the current audit: each tool's current
    description (to show hidden characters) and the contradicted tools."""

    def __init__(self, snapshot: MCPSnapshot | None, entries: tuple[AuditEntry, ...]) -> None:
        self.texts: dict[tuple[str | None, str, int], str] = {}
        if snapshot is not None:
            seen: dict[tuple[str | None, str], int] = {}
            for tool in snapshot.all_tools():
                if tool.parse_error is not None:
                    continue  # not fingerprinted either, so ranks match the lock's
                rank = seen.get((tool.server, tool.name), 0)
                seen[(tool.server, tool.name)] = rank + 1
                self.texts[(tool.server, tool.name, rank)] = tool.description
        self.contradicted = {e.label for e in entries if e.kind == "tool"
                             and any(f.category == CONTRADICTION for f in e.findings)}


def compare(locked: LockFile, current: LockFile, entries: tuple[AuditEntry, ...],
            ruleset: RuleSet, unreachable: set[str] | None = None,
            snapshot: MCPSnapshot | None = None) -> tuple[AuditEntry, ...]:
    """Merge lock differences into the audit. Tools of servers that could not
    be reached are not reported as removed (they get live-discovery-failed).
    `current` must be built with the locked salt and version; `snapshot`
    (the current capture) lets a description change show its hidden
    characters."""
    if locked.mode != current.mode:
        hint = "add --live" if locked.mode == "live" else "drop --live"
        raise ConfigFormatError(
            f"the lock file was created in {locked.mode} mode; {hint} to compare")
    changes: Changes = {}
    _server_changes(locked, current, changes)
    removed = _tool_changes(locked, current, unreachable or set(), changes,
                            _Context(snapshot, entries))
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


def changes_since(locked: LockFile, snap: MCPSnapshot, ruleset: RuleSet,
                  ) -> list[tuple[str, Finding]]:
    """Every lock difference between `locked` and the current snapshot, as
    (item label, finding). Compared in the lock's own format version."""
    current = fingerprint(snap, salt=locked.salt, version=locked.version)
    entries = compare(locked, current, analyze(snap, ruleset), ruleset, None, snap)
    return [(e.label, f) for e in entries for f in e.findings if f.category in LOCK_CATEGORIES]


def migrated(locked: LockFile, snap: MCPSnapshot) -> LockFile:
    """The same setup, fingerprinted in the current format, keeping the salt;
    command pins are recomputed (`lock --update` replaces them)."""
    return fingerprint(snap, salt=locked.salt, pins=True)


def tool_prints(tools: tuple[ToolSnapshot, ...], server: str | None,
                version: int = LOCK_VERSION) -> list[ToolPrint]:
    """Fingerprints of one server's tools (the proxy compares them live)."""
    return _tool_prints(tools, server, version)


def diff_tools(old: list[ToolPrint], new: list[ToolPrint],
               texts: dict[tuple[str | None, str, int], str] | None = None,
               ) -> list[tuple[str, Finding]]:
    """(label, finding) for every tool added, changed or removed between two
    sets of fingerprints, with the same severities as `inspect --lock`."""
    before = {t.key: t for t in old}
    after = {t.key: t for t in new}
    found: list[tuple[str, Finding]] = []
    for key in sorted(after.keys() - before.keys(), key=str):
        found.append((after[key].label, Finding(category="tool-added", risk=Risk.MEDIUM,
                                                evidence="not in the reference list")))
    for key in sorted(before.keys() & after.keys(), key=str):
        found += [(after[key].label, change)
                  for change in _tool_change(before[key], after[key], (texts or {}).get(key))]
    for key in sorted(before.keys() - after.keys(), key=str):
        found.append((before[key].label, Finding(category="tool-removed", risk=Risk.LOW,
                                                 evidence="no longer listed")))
    return found
