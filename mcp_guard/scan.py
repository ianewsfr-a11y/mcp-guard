"""`scan`: audit every MCP client configuration found on this machine.

Static only: files are read, no server is started or contacted. Each
config is audited with the same analysis as `inspect`. A server configured
in several places (same command, arguments, environment, headers and URL,
the only fields the analysis reads) is audited once; every place it
appears is kept in `ScannedServer.locations`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .analyzer import server_entry
from .clients import Location
from .collector import collect
from .formats import load_config
from .models import AuditEntry, ConfigFormatError, Risk
from .rules import RuleSet
from .snapshot import ServerSnapshot

MAX_CONFIG_BYTES = 10 * 1024 * 1024  # a config larger than this is not read
# What server findings depend on, plus `disabled`: a server the client never
# runs is not called "the same server" as one it runs.
_ANALYZED = ("command", "args", "env", "headers", "url")

Status = Literal["ok", "no-servers", "error"]


@dataclass(frozen=True)
class Occurrence:
    """One place a server is configured."""

    client: str
    path: Path
    section: str | None  # Claude Code: "user" or "project <path>" in ~/.claude.json
    name: str


@dataclass(frozen=True)
class ConfigResult:
    location: Location
    status: Status
    section: str | None = None
    error: str | None = None
    servers: tuple[tuple[str, str], ...] = ()  # (name in this config, server id)


@dataclass(frozen=True)
class ScannedServer:
    id: str  # s1, s2...: a server's place in this report, not derived from its content
    entry: AuditEntry  # audited once, named as where it was first found
    locations: tuple[Occurrence, ...]

    @property
    def risk(self) -> Risk:
        return self.entry.risk


@dataclass(frozen=True)
class ScanResult:
    searched: tuple[Location, ...]
    configs: tuple[ConfigResult, ...]
    servers: tuple[ScannedServer, ...]

    @property
    def highest(self) -> Risk | None:
        """None when no server has a finding."""
        return max((s.risk for s in self.servers if s.entry.findings), default=None)


def _read(location: Location) -> Any:
    path = location.path
    if location.scope == "project" and (path.is_symlink() or path.parent.is_symlink()):
        # a cloned repository could point it at any file of the user
        raise ConfigFormatError("a symbolic link in the project: not followed")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ConfigFormatError(f"larger than {MAX_CONFIG_BYTES // (1024 * 1024)} MB, not read")
    try:
        return load_config(path)
    except RecursionError as exc:
        raise ConfigFormatError("nested too deeply to be read") from exc


def _claude_code_sections(data: Any) -> list[tuple[str, Any]]:
    """~/.claude.json: user-scope servers at the top, local-scope servers
    under `projects.<path>.mcpServers`. The rest of the file is not read."""
    if not isinstance(data, dict):
        return []
    sections: list[tuple[str, Any]] = []
    if isinstance(data.get("mcpServers"), dict):
        sections.append(("user", {"mcpServers": data["mcpServers"]}))
    projects = data.get("projects")
    for project, settings in (projects.items() if isinstance(projects, dict) else ()):
        servers = settings.get("mcpServers") if isinstance(settings, dict) else None
        if isinstance(servers, dict) and servers:
            sections.append((f"project {project}", {"mcpServers": servers}))
    return sections


def _sections(location: Location, data: Any) -> list[tuple[str | None, Any]]:
    if location.reader == "claude-code":
        return list(_claude_code_sections(data))
    return [(None, data)]


_SERVER_KEYS = ("mcpServers", "servers", "context_servers")


def _wrong_shape(data: Any) -> str | None:
    """A known server key that holds neither an object nor a list."""
    if not isinstance(data, dict):
        return None
    for key in _SERVER_KEYS:
        if key in data and data[key] is not None and not isinstance(data[key], (dict, list)):
            return f"`{key}` is not an object"
    return None


def _key(server: ServerSnapshot, where: Occurrence) -> str:
    """Same key, same findings. A malformed entry is never merged."""
    if server.spec is None:
        return json.dumps(["malformed", str(where.path), where.section, where.name])
    fields = server.spec.model_dump(mode="json", include=set(_ANALYZED))
    return json.dumps([fields, server.disabled], sort_keys=True, default=str)


@dataclass
class _Builder:
    """Accumulates one scan. Private and short-lived; the result is frozen."""

    ruleset: RuleSet
    configs: list[ConfigResult]
    entries: dict[str, AuditEntry]
    ids: dict[str, str]
    occurrences: dict[str, list[Occurrence]]

    def server(self, server: ServerSnapshot, where: Occurrence) -> str:
        key = _key(server, where)
        if key not in self.ids:
            self.ids[key] = f"s{len(self.ids) + 1}"
            self.entries[key] = server_entry(server, self.ruleset)
            self.occurrences[key] = []
        self.occurrences[key].append(where)
        return self.ids[key]

    def section(self, location: Location, section: str | None, data: Any) -> None:
        shape = _wrong_shape(data)
        if shape:
            self.configs.append(ConfigResult(location, "error", section, error=shape))
            return
        try:
            snapshot = collect(data, str(location.path))
        except ConfigFormatError:
            self.configs.append(ConfigResult(location, "no-servers", section))
            return
        names = tuple(
            (s.name, self.server(s, Occurrence(location.client, location.path, section, s.name)))
            for s in snapshot.servers)
        status: Status = "ok" if names else "no-servers"
        self.configs.append(ConfigResult(location, status, section, servers=names))

    def location(self, location: Location) -> None:
        try:
            data = _read(location)
            sections = _sections(location, data)
            if not sections:
                self.configs.append(ConfigResult(location, "no-servers"))
            for section, part in sections:
                self.section(location, section, part)
        except (ConfigFormatError, OSError, ValueError) as exc:
            self.configs.append(ConfigResult(location, "error", error=str(exc)))
        except Exception as exc:  # fail-open: one odd file never stops the scan  # noqa: BLE001
            self.configs.append(ConfigResult(location, "error",
                                             error=f"internal error ({type(exc).__name__})"))


def existing(searched: Iterable[Location]) -> tuple[Location, ...]:
    return tuple(loc for loc in searched if loc.path.is_file())


def scan(searched: tuple[Location, ...], ruleset: RuleSet) -> ScanResult:
    builder = _Builder(ruleset, [], {}, {}, {})
    for location in existing(searched):
        builder.location(location)
    servers = tuple(ScannedServer(builder.ids[key], builder.entries[key],
                                  tuple(builder.occurrences[key]))
                    for key in builder.ids)
    return ScanResult(searched=searched, configs=tuple(builder.configs), servers=servers)
