"""What --live would run, shown to the user before anything starts."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from ..analysis import redact_args, safe_url
from ..models import ServerSpec
from ..text import printable
from .protocol import LiveError

# Variables that make a trusted launcher (node, python, a shell) load code.
_CODE_LOADING_ENV = re.compile(
    r"^(NODE_OPTIONS|NODE_PATH|LD_\w+|DYLD_\w+|PYTHON\w*|PERL5\w*|RUBY\w*|"
    r"BASH_ENV|ENV|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|PATH|PATHEXT|COMSPEC)$",
    re.IGNORECASE)
_DISPLAY_LIMIT = 300


def resolve_executable(command: str, cwd: Path | None = None) -> str:
    """Absolute path of the program to start.

    A bare name (`npx`) must be found on PATH and must not resolve to the
    current directory: Windows searches it first, so a repository could
    plant `npx.cmd` next to the config being audited. An explicit path
    (`./server`, `C:\\tools\\srv.exe`) is used as written."""
    if not command:
        raise LiveError("empty `command`")
    if "/" in command or "\\" in command:
        return str(Path(command).expanduser())
    found = shutil.which(command)
    if not found:
        raise LiveError(f"{printable(command, 80)!r} was not found on PATH")
    here = (cwd or Path.cwd()).resolve()
    if Path(found).resolve().parent == here:
        raise LiveError(f"refusing to run {printable(command, 80)!r}: it resolves to the "
                        f"current directory (possible planted binary); use an explicit path")
    return found


def describe_launch(server: ServerSpec) -> str:
    """One line describing what will run, with secrets redacted and control
    characters neutralized."""
    if server.url:
        return printable(f"connect to {safe_url(server.url)}", _DISPLAY_LIMIT)
    try:
        program = resolve_executable(server.command)
    except LiveError as exc:
        return printable(f"cannot run: {exc}", _DISPLAY_LIMIT)
    line = " ".join([program, *redact_args([str(a) for a in server.args])])
    if server.env:
        line += f"  [env: {', '.join(sorted(map(str, server.env)))}]"
    return printable(line, _DISPLAY_LIMIT)


def launch_warnings(server: ServerSpec) -> list[str]:
    risky = sorted(k for k in map(str, server.env) if _CODE_LOADING_ENV.match(k))
    if not risky:
        return []
    return [printable(f"env {', '.join(risky)} can make the program load other code",
                      _DISPLAY_LIMIT)]
