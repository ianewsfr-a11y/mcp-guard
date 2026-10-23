"""What the proxy compares against: the lock entry of the server it wraps.

Matching, in order:

1. `--server-name NAME`, when given;
2. the entry whose pinned program and arguments equal the command seen;
3. the only entry that runs the same program (its arguments changed:
   `command-pin-changed` says so);
4. the only server of the lock, when it has just one.

Two entries with the same program and arguments (a copy-pasted config) are
ambiguous: the proxy does not guess, it asks for `--server-name`. Ambiguity,
no match, a missing or unreadable lock: none of these stops the proxy. It
runs in "session only" mode (each tools/list is compared with the previous
one) and says why on stderr.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ..identity import ServerIdentity
from ..lock import LockFile, ToolPrint, read_lock
from ..models import ConfigFormatError, Finding
from ..pin import Pin, compare_pins, compute_pin
from ..text import printable

Warn = Callable[[str], None]


class LockContext(BaseModel):
    """The locked view of one server; `server is None` means session only."""

    model_config = ConfigDict(frozen=True)

    server: str | None = None
    version: int = 2
    tools: tuple[ToolPrint, ...] | None = None  # None: the lock has no live tools
    identity: ServerIdentity | None = None
    instructions: str | None = None  # hash (lock v3, live); None: nothing to compare
    pin_findings: tuple[Finding, ...] = ()


def _choose(lock: LockFile, pin: Pin, name: str | None, shown: str,
            warn: Warn) -> str | None:
    if name is not None:
        if name in lock.servers:
            return name
        warn(f"--server-name {printable(name, 80)!r} is not in the lock: session only")
        return None
    matching = sorted(n for n, s in lock.servers.items()
                      if s.pin is not None and s.pin.launch_key == pin.launch_key)
    if len(matching) == 1:
        return matching[0]
    if len(matching) > 1:
        warn(f"several lock entries run {shown} ({', '.join(map(repr, matching))}): "
             "pass --server-name to choose; session only until then")
        return None
    same_program = [n for n, s in lock.servers.items()
                    if s.pin is not None and s.pin.program == pin.program]
    if len(same_program) == 1:
        warn(f"no lock entry runs {shown} exactly; comparing with {printable(same_program[0], 80)!r}, "
             f"the only entry that runs {printable(pin.program, 40)}. If this is another server, pass "
             "--server-name")
        return same_program[0]
    if len(lock.servers) == 1:
        return next(iter(lock.servers))
    warn(f"no lock entry runs {shown}; if its command changed, pass --server-name to "
         "compare it. Session only")
    return None


def _context(lock: LockFile, server: str, pin: Pin, warn: Warn) -> LockContext:
    entry = lock.servers[server]
    findings: list[Finding] = []
    if entry.pin is not None:
        findings, notes = compare_pins(entry.pin, pin)
        for note in notes:
            warn(f"{printable(server, 80)}: {note}")
    else:
        warn(f"the lock has no command pin for {printable(server, 80)!r} "
             "(run `mcp-guard lock --update` to add one)")
    tools = tuple(t for t in lock.tools if t.server == server) if lock.mode == "live" else None
    if tools is None:
        warn("the lock was made without --live: it has no tools to compare; "
             "comparing within this session only")
    return LockContext(server=server, version=lock.version, tools=tools,
                       identity=entry.identity,
                       instructions=entry.instructions if lock.mode == "live" else None,
                       pin_findings=tuple(findings))


def load(lock_path: Path | None, command: str, args: list[str], name: str | None,
         warn: Warn) -> LockContext:
    """Never raises: every problem is reported and gives a session-only context."""
    if lock_path is None:
        warn("no --lock: comparing within this session only")
        return LockContext()
    try:
        lock = read_lock(lock_path)
    except (ConfigFormatError, RecursionError, ValueError) as exc:
        warn(f"lock not used ({printable(str(exc), 300)}): session only")
        return LockContext()
    try:
        pin = compute_pin(command, args, lock.salt)
        shown = printable(" ".join([command, *pin.args]), 200)
        server = _choose(lock, pin, name, shown, warn)
        return LockContext() if server is None else _context(lock, server, pin, warn)
    except Exception as exc:  # fail-open: a hostile lock or path never stops the proxy  # noqa: BLE001
        warn(f"lock not used (internal error: {type(exc).__name__}): session only")
        return LockContext()
