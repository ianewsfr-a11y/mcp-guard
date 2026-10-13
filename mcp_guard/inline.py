"""Servers given on the command line (`--server "npx -y pkg"`) instead of a file."""

from __future__ import annotations

import re
import shlex
import sys
from typing import Any

from .models import ConfigFormatError

SOURCE_LABEL = "command line"


def split_command(command: str) -> list[str]:
    """Split like the user's shell would. On Windows, backslashes in paths
    are kept and surrounding quotes removed."""
    try:
        if sys.platform == "win32":
            return [part[1:-1] if len(part) > 1 and part[0] == part[-1] and part[0] in "\"'"
                    else part for part in shlex.split(command, posix=False)]
        return shlex.split(command)
    except ValueError as exc:  # unbalanced quotes
        raise ConfigFormatError(f"cannot parse --server {command!r}: {exc}") from exc


def _clean(part: str) -> str:
    """`@scope/pkg@1.2` -> `pkg`, `C:\\srv\\index.js` -> `index`."""
    if part.startswith("@"):
        part = part.split("/", 1)[-1]
    part = re.split(r"[\\/]", part.split("@")[0])[-1]
    return re.sub(r"\.(py|js|mjs|cjs|ts|exe)$", "", part, flags=re.IGNORECASE)


def _base_name(parts: list[str]) -> str:
    """A readable server name: the package or script it runs (an argument
    that looks like one), else the first plain argument, else the program."""
    plain = [p for p in parts[1:] if not p.startswith("-")]
    looks_like_package = [p for p in plain if re.search(r"[./@-]", p)]
    for part in looks_like_package + plain:
        if _clean(part):
            return _clean(part)
    return _clean(parts[0])


def servers_from_cli(values: tuple[str, ...]) -> dict[str, Any]:
    """An `mcpServers` config built from repeated --server values."""
    servers: dict[str, Any] = {}
    for value in values:
        value = value.strip()
        if re.match(r"https?://", value, re.IGNORECASE):
            spec: dict[str, Any] = {"url": value}
            base = re.sub(r"^https?://([^/:?#]+).*$", r"\1", value, flags=re.IGNORECASE)
        else:
            parts = split_command(value)
            if not parts:
                raise ConfigFormatError("--server needs a command or an http(s) URL")
            spec = {"command": parts[0], "args": parts[1:]}
            base = _base_name(parts)
        name, n = base or "server", 2
        while name in servers:
            name, n = f"{base} #{n}", n + 1
        servers[name] = spec
    return {"mcpServers": servers}
