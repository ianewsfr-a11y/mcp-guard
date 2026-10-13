"""Loading config files (JSON, JSONC, YAML) and detecting the MCP format."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, NamedTuple

import yaml

from .models import ConfigFormatError


class Discovered(NamedTuple):
    servers: dict[str, Any]
    tools: list[Any]
    format: str


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

_JSON_STRING = r'("(?:\\.|[^"\\])*")'
_COMMENTS = re.compile(_JSON_STRING + r"|//[^\n]*|/\*.*?\*/", re.DOTALL)
_TRAILING_COMMAS = re.compile(_JSON_STRING + r"|,(\s*[}\]])")
_YAML_SUFFIXES = frozenset({".yaml", ".yml"})


def strip_jsonc(text: str) -> str:
    """Remove comments and trailing commas (VS Code / Zed style) outside strings."""
    text = _COMMENTS.sub(lambda m: m.group(1) or "", text)
    return _TRAILING_COMMAS.sub(lambda m: m.group(1) or m.group(2), text)


def _parse_json(text: str, path: Path) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(strip_jsonc(text))
    except json.JSONDecodeError as exc:
        raise ConfigFormatError(
            f"{path} is not valid JSON (comments and trailing commas are "
            f"accepted): {exc}") from exc


def _parse_yaml(text: str, path: Path) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigFormatError(f"{path} is not valid YAML: {exc}") from exc


def load_config(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigFormatError(f"{path} is not UTF-8 text: {exc}") from exc
    if path.suffix.lower() in _YAML_SUFFIXES:
        return _parse_yaml(text, path)
    return _parse_json(text, path)


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

# (container path, key, label). Order matters: first match wins.
_SERVER_LOCATIONS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    ((), "mcpServers", "mcpServers (Claude Desktop / Cursor / Windsurf / Continue)"),
    ((), "servers", "servers (VS Code)"),
    (("mcp",), "servers", "mcp.servers (VS Code settings)"),
    ((), "context_servers", "context_servers (Zed)"),
)


def _dig(data: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        data = data.get(key) if isinstance(data, dict) else None
    return data


def _add_unique(servers: dict[str, Any], base: str, entry: Any) -> None:
    name, n = base, 2
    while name in servers:
        name, n = f"{base} #{n}", n + 1
    servers[name] = entry


def _find_servers(data: Any) -> tuple[dict[str, Any], list[str]] | None:
    """Merge servers from every known location (a VS Code or Zed settings
    file can hold several). Continue lists servers as `[{name: ...}]`."""
    servers: dict[str, Any] = {}
    labels: list[str] = []
    for path, key, label in _SERVER_LOCATIONS:
        found = _dig(data, path + (key,))
        if isinstance(found, dict):
            for name, entry in found.items():
                _add_unique(servers, str(name), entry)
            labels.append(label)
        elif isinstance(found, list) and key == "mcpServers":
            for index, entry in enumerate(found):
                name = entry.get("name") if isinstance(entry, dict) else None
                _add_unique(servers, str(name or f"server[{index}]"), entry)
            labels.append("mcpServers list (Continue YAML)")
    return (servers, labels) if labels else None


def _find_tools(data: Any) -> list[Any] | None:
    """A bare list, a `tools` key, or a JSON-RPC `tools/list` response."""
    if isinstance(data, list):
        return data
    for path in (("tools",), ("result", "tools")):
        found = _dig(data, path)
        if isinstance(found, list):
            return found
    return None


def discover(data: Any) -> Discovered:
    servers = _find_servers(data)
    tools = _find_tools(data)
    if servers is None and tools is None:
        raise ConfigFormatError(
            "No MCP servers (mcpServers / servers / context_servers) or tools list found."
        )
    labels = (servers[1] if servers else []) + (["tools list"] if tools is not None else [])
    return Discovered(servers=servers[0] if servers else {}, tools=tools or [],
                      format=" + ".join(labels))
