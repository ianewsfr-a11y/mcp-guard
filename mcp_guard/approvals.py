"""Approval log: who accepted a lock change, when and what (issue #34).

`inspect --lock` says that something changed; the pull request that updates
the lock gives the review context. `lock --approvals FILE` also appends one
JSON line per approval to FILE, easy to query later:

- `time`, `approver` (`--approver`, else the OS user name) and `reason`;
- `lock`: the lock file's name; `before` / `after`: SHA-256 of its bytes
  before and after (`before` is null for a new lock);
- `changes`: what the new lock approves, compared with the previous one
  (item, category, field, risk). Never the evidence, which quotes
  descriptions; never a secret;
- `compared`: false when the previous lock could not be compared (missing,
  unreadable, other mode), so `changes` is empty for that reason only;
- `previous`: SHA-256 of the previous line of the log. `mcp-guard approvals
  FILE` checks the chain: a line edited, inserted or removed in the middle
  breaks it. Removing the last lines does not: keep the log in git, or ship
  it elsewhere, if that matters.

The log is opt-in. Nothing is written without `--approvals`.
"""

from __future__ import annotations

import getpass
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_serializer, field_validator

from . import __version__
from .models import ConfigFormatError, Finding, Risk
from .text import printable

_SHA256 = r"^[0-9a-f]{64}$"
MAX_TEXT = 1000
MAX_CHANGES = 2000


class ApprovedChange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    item: str = Field(max_length=MAX_TEXT)
    category: str = Field(max_length=100)
    field: str | None = Field(default=None, max_length=MAX_TEXT)
    risk: Risk

    @field_validator("risk", mode="before")
    @classmethod
    def _risk_name(cls, value: object) -> Risk:
        return Risk.parse(value)

    @field_serializer("risk")
    def _risk_shown(self, risk: Risk) -> str:
        return risk.name  # readable in the log: "HIGH", not 2


class Approval(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    time: str
    approver: str = Field(max_length=MAX_TEXT)
    reason: str | None = Field(default=None, max_length=MAX_TEXT)
    lock: str = Field(max_length=MAX_TEXT)
    before: str | None = Field(default=None, pattern=_SHA256)
    after: str = Field(pattern=_SHA256)
    compared: bool = True
    changes: tuple[ApprovedChange, ...] = Field(default=(), max_length=MAX_CHANGES)
    previous: str | None = Field(default=None, pattern=_SHA256)
    generator: str = f"mcp-guard {__version__}"


def default_approver() -> str:
    try:
        return getpass.getuser()
    except (OSError, KeyError, ImportError):  # no user name in this environment
        return "unknown"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def approved_changes(changes: list[tuple[str, Finding]]) -> tuple[ApprovedChange, ...]:
    return tuple(ApprovedChange(item=label[:MAX_TEXT], category=f.category,
                                field=f.field[:MAX_TEXT] if f.field else None, risk=f.risk)
                 for label, f in changes[:MAX_CHANGES])


def _last_line(path: Path) -> bytes | None:
    try:
        lines = path.read_bytes().splitlines()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigFormatError(f"cannot read approval log {path}: {exc}") from exc
    return next((line for line in reversed(lines) if line.strip()), None)


def append(path: Path, approval: Approval) -> Approval:
    """Chain `approval` to the log's last line and append it; return it."""
    last = _last_line(path)
    entry = approval.model_copy(update={
        "previous": sha256(last) if last is not None else None,
        "time": approval.time or datetime.now(timezone.utc).isoformat(timespec="seconds")})
    line = entry.model_dump_json(exclude_none=True)
    try:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
    except OSError as exc:
        raise ConfigFormatError(f"cannot write approval log {path}: {exc}") from exc
    return entry


def read_log(path: Path) -> tuple[list[Approval], list[str]]:
    """The entries, and the problems found: unreadable lines, broken chain."""
    try:
        lines = [line for line in path.read_bytes().splitlines() if line.strip()]
    except OSError as exc:
        raise ConfigFormatError(f"cannot read approval log {path}: {exc}") from exc
    entries: list[Approval] = []
    problems: list[str] = []
    previous: bytes | None = None
    for number, line in enumerate(lines, 1):
        try:
            entry = Approval.model_validate(json.loads(line))
        except (ValueError, ValidationError, RecursionError):
            problems.append(f"line {number}: not an approval entry")
            previous = line
            continue
        expected = sha256(previous) if previous is not None else None
        if entry.previous != expected:
            problems.append(f"line {number}: the chain is broken (a line before it was "
                            "edited, inserted or removed)")
        entries.append(entry)
        previous = line
    return entries, problems


def describe(entry: Approval) -> str:
    """One line per approval, safe for a terminal."""
    what = (f"{len(entry.changes)} change(s)" if entry.compared
            else "previous lock not compared")
    reason = f": {printable(entry.reason, 200)}" if entry.reason else ""
    return (f"{printable(entry.time, 40)}  {printable(entry.approver, 60)} approved "
            f"{printable(entry.lock, 80)} ({what}){reason}")
