"""Where MCP clients keep their server configuration, per operating system.

Used by `scan`. Every location says whether its path is confirmed by the
client's official documentation or source (`verified`, with the URL in
`source`). A path that could not be confirmed is kept and marked "not
verified", with the reason, rather than presented as documented. Checked
on 2026-10-15. Nothing here reads a file: `locations` only builds paths,
so it can be tested with any home directory and environment.

Two clients moved their files: Windsurf (now Devin Desktop) documents
`~/.config/devin/mcp_config.json`, and Cline `~/.cline/data/settings/`.
Their former paths are still searched, marked "not verified".
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal

System = Literal["Windows", "Darwin", "Linux"]
Scope = Literal["user", "project"]
Reader = Literal["config", "claude-code"]  # claude-code: user and per-project sections

CLAUDE_DESKTOP, CLAUDE_CODE, CURSOR, VSCODE = "Claude Desktop", "Claude Code", "Cursor", "VS Code"
WINDSURF, ZED, CONTINUE, CLINE, ROO = "Windsurf", "Zed", "Continue", "Cline", "Roo Code"
CLIENTS = (CLAUDE_DESKTOP, CLAUDE_CODE, CURSOR, VSCODE, WINDSURF, ZED, CONTINUE, CLINE, ROO)

CLINE_EXTENSION = "saoudrizwan.claude-dev"
ROO_EXTENSION = "rooveterinaryinc.roo-cline"

_CLAUDE_CODE_DOCS = "https://code.claude.com/docs/en/mcp"
_VSCODE_DOCS = "https://code.visualstudio.com/docs/copilot/customization/mcp-servers"
_NO_FOLDER = ("not verified: the docs name the file but not its folder, inferred from the "
              "VS Code user data folder (default profile)")


@dataclass(frozen=True)
class Location:
    client: str
    path: Path
    scope: Scope
    verified: bool  # confirmed by the client's official documentation or source
    source: str  # the URL that confirms it, or "not verified: <why>"
    reader: Reader = "config"


@dataclass(frozen=True)
class _Dirs:
    """The per-OS base directories of one user."""

    home: Path
    cwd: Path
    app_data: Path  # %APPDATA%, ~/Library/Application Support, or the XDG config dir
    config: Path  # $XDG_CONFIG_HOME or ~/.config, on macOS and Linux
    env: Mapping[str, str]
    system: System


def _absolute(value: str | None, windows: bool) -> bool:
    if not value:
        return False
    return (PureWindowsPath(value) if windows else PurePosixPath(value)).is_absolute()


def _dirs(home: Path, cwd: Path, env: Mapping[str, str], system: System) -> _Dirs:
    xdg = env.get("XDG_CONFIG_HOME")
    config = Path(xdg) if xdg and _absolute(xdg, False) else home / ".config"
    if system == "Windows":
        given = env.get("APPDATA")
        app_data = Path(given) if given and _absolute(given, True) else home / "AppData" / "Roaming"
    elif system == "Darwin":
        app_data = home / "Library" / "Application Support"
    else:
        app_data = config
    return _Dirs(home, cwd, app_data, config, env, system)


def _claude_desktop(d: _Dirs) -> list[Location]:
    path = d.app_data / "Claude" / "claude_desktop_config.json"
    if d.system == "Linux":
        return [Location(CLAUDE_DESKTOP, path, "user", False,
                         "not verified: the docs give no Linux path")]
    return [Location(CLAUDE_DESKTOP, path, "user", True,
                     "https://modelcontextprotocol.io/docs/develop/connect-local-servers")]


def _claude_code(d: _Dirs) -> list[Location]:
    windows = d.system == "Windows"
    user = (Location(CLAUDE_CODE, d.home / ".claude.json", "user", False,
                     "not verified: the docs give ~/.claude.json, not its Windows path",
                     "claude-code") if windows else
            Location(CLAUDE_CODE, d.home / ".claude.json", "user", True, _CLAUDE_CODE_DOCS,
                     "claude-code"))
    return [user, Location(CLAUDE_CODE, d.cwd / ".mcp.json", "project", True, _CLAUDE_CODE_DOCS)]


def _cursor(d: _Dirs) -> list[Location]:
    docs = "https://cursor.com/docs/context/mcp"
    return [Location(CURSOR, d.home / ".cursor" / "mcp.json", "user", True, docs),
            Location(CURSOR, d.cwd / ".cursor" / "mcp.json", "project", True, docs)]


def _vscode_user(d: _Dirs) -> Path:
    return d.app_data / "Code" / "User"


def _vscode(d: _Dirs) -> list[Location]:
    copilot = d.env.get("COPILOT_HOME")
    copilot_home = Path(copilot) if copilot and _absolute(copilot, d.system == "Windows") \
        else d.home / ".copilot"
    return [Location(VSCODE, _vscode_user(d) / "mcp.json", "user", False, _NO_FOLDER),
            Location(VSCODE, copilot_home / "mcp-config.json", "user", True, _VSCODE_DOCS),
            Location(VSCODE, d.cwd / ".vscode" / "mcp.json", "project", True, _VSCODE_DOCS)]


def _windsurf(d: _Dirs) -> list[Location]:
    base = d.app_data if d.system == "Windows" else d.config
    return [Location(WINDSURF, base / "devin" / "mcp_config.json", "user", True,
                     "https://docs.devin.ai/desktop/cascade/mcp"),
            Location(WINDSURF, d.home / ".codeium" / "windsurf" / "mcp_config.json", "user",
                     False, "not verified: former path, no longer in the docs")]


def _zed(d: _Dirs) -> list[Location]:
    base = d.app_data / "Zed" if d.system == "Windows" else d.config / "zed"
    if d.system == "Darwin":
        base = d.home / ".config" / "zed"
    return [Location(ZED, base / "settings.json", "user", True,
                     "https://github.com/zed-industries/zed/blob/main/docs/src/"
                     "configuring-zed.md")]


def _continue(d: _Dirs) -> list[Location]:
    return [Location(CONTINUE, d.home / ".continue" / "config.yaml", "user", True,
                     "https://github.com/continuedev/continue/blob/main/docs/customize/"
                     "deep-dives/configuration.mdx")]


def _extension(d: _Dirs, client: str, extension: str, name: str, why: str) -> Location:
    path = _vscode_user(d) / "globalStorage" / extension / "settings" / name
    return Location(client, path, "user", False, why)


def _cline_roo(d: _Dirs) -> list[Location]:
    return [
        Location(CLINE, d.home / ".cline" / "data" / "settings" / "cline_mcp_settings.json",
                 "user", True, "https://github.com/cline/cline/blob/main/docs/mcp/"
                               "mcp-overview.mdx"),
        _extension(d, CLINE, CLINE_EXTENSION, "cline_mcp_settings.json",
                   "not verified: former VS Code extension storage, migrated by Cline"),
        _extension(d, ROO, ROO_EXTENSION, "mcp_settings.json",
                   "not verified: file name from the Roo Code docs, folder inferred from "
                   "the VS Code extension storage"),
    ]


def locations(home: Path, cwd: Path, env: Mapping[str, str],
              system: System) -> tuple[Location, ...]:
    """Every known location, in client order; a path is listed once (the
    first client keeps it: `./.mcp.json` is Claude Code's and VS Code's)."""
    d = _dirs(home, cwd, env, system)
    found = [*_claude_desktop(d), *_claude_code(d), *_cursor(d), *_vscode(d),
             *_windsurf(d), *_zed(d), *_continue(d), *_cline_roo(d)]
    seen: set[Path] = set()
    unique = []
    for location in found:
        if location.path not in seen:
            seen.add(location.path)
            unique.append(location)
    return tuple(unique)
