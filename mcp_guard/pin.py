"""Command pinning: what exactly a stdio server runs.

`mcp-guard lock` records, per stdio server, the resolved executable, its
arguments (secrets redacted, as everywhere in a lock), the SHA-256 of the
executable and of the script it runs when readable (`node server.js`), and
the date. `mcp-guard proxy` recomputes it at start and compares.

The lock is committed and shared, and `npx` lives in a different place on
every machine, so the comparison is about content first:

- a different executable or script hash, different arguments, or a
  different program name: HIGH (`command-pin-changed`);
- the same program and hashes at another path: a note, not a finding.

The lock is committed, so arguments are stored in a strict display form
(secrets, URL paths and queries, token-like words and the home directory
removed) and compared through a salted HMAC of their exact value
(`args_hmac`, keyed with the lock's salt): a change is detected without the
lock holding the value.

The salt sits in the lock itself (`salt`, 16 random bytes): the HMAC only
defeats precomputed tables. Anyone who reads the lock can test guesses, so
a low-entropy secret in the arguments can be recovered from it.
`secret_args` names those arguments (`secret-in-args`): move them to the
environment, where the lock keeps only their names.

The home directory is stored as `~`, so the lock does not publish a user
name. Pinning the package an `npx` or `uvx` launcher downloads (its npm or
PyPI digest) is out of scope: see ROADMAP.md.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .live.launch import resolve_executable
from .live.protocol import LiveError
from .models import Finding, Risk
from .redact import REDACTED, SECRET_WORDS, TOKEN, URL_ORIGIN, redact_args

CATEGORY = "command-pin-changed"
MAX_HASHED_BYTES = 1024 * 1024 * 1024
_SHA256 = r"^[0-9a-f]{64}$"
_LAUNCHER_SUFFIX = re.compile(r"\.(exe|cmd|bat|com|ps1)$", re.IGNORECASE)


class Pin(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    executable: str  # resolved path, home directory as `~`
    command: str | None = None  # the name as written in the config (`npx`)
    args: tuple[str, ...] = ()  # strict display form, see `stored_arg`
    args_hmac: str | None = Field(default=None, pattern=_SHA256)  # exact args, salted
    executable_sha256: str | None = Field(default=None, pattern=_SHA256)
    script: str | None = None  # the file the program runs, if any
    script_sha256: str | None = Field(default=None, pattern=_SHA256)
    pinned_at: str = ""

    @property
    def program(self) -> str:
        """`npx`, `node`, `python`: the name written in the config (a symlink
        such as `python` -> `python3.12` resolves differently on each
        machine), whatever the path or suffix."""
        name = re.split(r"[\\/]", self.command or self.executable)[-1]
        return _LAUNCHER_SUFFIX.sub("", name).lower()

    @property
    def launch_key(self) -> tuple[str, str | tuple[str, ...]]:
        """What identifies a server across machines: program and arguments."""
        return self.program, self.args_hmac or self.args


def _home() -> str:
    try:
        return str(Path.home()).rstrip("\\/")
    except (RuntimeError, KeyError, OSError):
        return ""


def portable(path: str) -> str:
    """The path with the home directory written `~` (at a path boundary)."""
    home = _home()
    if not home:
        return path
    folded, base = os.path.normcase(path), os.path.normcase(home)
    if folded == base or (folded.startswith(base) and path[len(home)] in "\\/"):
        return "~" + path[len(home):]
    return path


def _stored_url(match: re.Match[str]) -> str:
    origin, whole = match.group(1), match.group(0)
    if "@" in origin:
        return REDACTED  # userinfo
    return origin + ("/" + REDACTED if len(whole) > len(origin) else "")


def stored_arg(arg: str) -> str:
    """An argument as the committed lock shows it: stricter than display
    redaction (only scheme and host of a URL, no token-like word, `~` for
    the home directory), since `args_hmac` detects any change anyway."""
    if SECRET_WORDS.search(arg):
        return REDACTED
    home = _home()
    if home and home in arg:
        arg = arg.replace(home, "~")
    return TOKEN.sub(REDACTED, URL_ORIGIN.sub(_stored_url, arg))


def stored_args(args: list[str]) -> tuple[str, ...]:
    return tuple(stored_arg(arg) for arg in redact_args(args))


def args_hmac(args: list[str], salt: str) -> str:
    canonical = json.dumps(args, ensure_ascii=False, separators=(",", ":"))
    return hmac.new(bytes.fromhex(salt), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def sha256_file(path: Path) -> str | None:
    """Hash of a readable regular file; None when it cannot be read. The
    type is checked on the open descriptor, without blocking: a FIFO
    swapped in after a check must not hang the start."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except (OSError, ValueError):
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_HASHED_BYTES:
            return None
        digest = hashlib.sha256()
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def _script(args: list[str]) -> Path | None:
    """The first argument that is an existing file (`server.js`, `srv.py`)."""
    for arg in args:
        if arg.startswith("-"):
            continue
        try:
            candidate = Path(arg).expanduser()
            if candidate.is_file():
                return candidate.resolve()
        except (OSError, RuntimeError, ValueError):  # ~nouser, symlink loop
            continue
        return None
    return None


def compute_pin(command: str, args: list[str], salt: str | None = None,
                now: str | None = None) -> Pin:
    """`salt` (the lock's) keys `args_hmac`; without it, arguments are only
    compared in their stored form."""
    try:
        executable = Path(resolve_executable(command)).resolve()
        exe_hash = sha256_file(executable)
        shown = portable(str(executable))
    except (LiveError, OSError, RuntimeError, ValueError):
        exe_hash, shown = None, portable(command)  # not resolvable here: the name only
    script = _script(args)
    return Pin(executable=shown, command=portable(command), args=stored_args(args),
               args_hmac=args_hmac(args, salt) if salt else None,
               executable_sha256=exe_hash,
               script=portable(str(script)) if script else None,
               script_sha256=sha256_file(script) if script else None,
               pinned_at=now or datetime.now(timezone.utc).isoformat(timespec="seconds"))


def _differences(old: Pin, new: Pin) -> list[str]:
    changes = []
    if old.program != new.program:
        changes.append(f"program {old.program!r} -> {new.program!r}")
    same_args = (old.args_hmac == new.args_hmac if old.args_hmac and new.args_hmac
                 else old.args == new.args)
    if not same_args:
        changes.append("arguments changed")
    if old.executable_sha256 and new.executable_sha256 \
            and old.executable_sha256 != new.executable_sha256:
        changes.append("executable content changed (sha256)")
    if old.script_sha256 and new.script_sha256 and old.script_sha256 != new.script_sha256:
        changes.append(f"script content changed (sha256): {new.script}")
    return changes


def _unverifiable(old: Pin, new: Pin) -> list[str]:
    """Hashes the lock has but this machine cannot compute: said, not hidden."""
    notes = []
    if old.executable_sha256 and not new.executable_sha256:
        notes.append(f"{new.executable} cannot be hashed here: its content is not verified")
    if old.script_sha256 and not new.script_sha256:
        notes.append(f"{old.script} cannot be hashed here: its content is not verified")
    return notes


def compare_pins(old: Pin, new: Pin) -> tuple[list[Finding], list[str]]:
    """(findings, notes): content changes are HIGH; a move is only a note."""
    changes = _differences(old, new)
    notes = _unverifiable(old, new)
    if changes:
        since = f" since {old.pinned_at or 'the lock'}"
        return [Finding(category=CATEGORY, risk=Risk.HIGH,
                        evidence="; ".join(changes) + since)], notes
    if old.executable != new.executable:
        notes.append(f"same program at another path ({old.executable} -> {new.executable})")
    return [], notes
