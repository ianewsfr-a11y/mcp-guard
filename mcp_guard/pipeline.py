"""One audit run, shared by `inspect` and `ui`:
collect (config, then live) -> snapshot -> analyze -> compare with a lock."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analyzer import analyze
from .collector import Outcome, collect
from .lock import LockFile, compare, fingerprint, read_lock
from .models import AuditEntry
from .rules import RuleSet
from .snapshot import MCPSnapshot


@dataclass(frozen=True)
class AuditRun:
    source: str
    snapshot: MCPSnapshot
    entries: tuple[AuditEntry, ...]
    ruleset: RuleSet
    lock: LockFile | None = None
    lock_path: Path | None = None


def audit_snapshot(snap: MCPSnapshot, ruleset: RuleSet, lock_path: Path | None = None,
                   ) -> tuple[tuple[AuditEntry, ...], LockFile | None]:
    """Findings for a snapshot, plus lock differences if a lock is given.
    Raises ConfigFormatError on an unreadable or incompatible lock."""
    entries = analyze(snap, ruleset)
    if not lock_path:
        return entries, None
    locked = read_lock(lock_path)
    unreachable = {s.name for s in snap.servers if s.live_status == "failed"}
    current = fingerprint(snap, salt=locked.salt, version=locked.version)
    return compare(locked, current, entries, ruleset, unreachable, snap), locked


def run_audit(data: Any, source: str, ruleset: RuleSet,
              live: Mapping[str, Outcome] | None = None,
              lock_path: Path | None = None) -> AuditRun:
    """Audit `data` (with live results if given). Raises ConfigFormatError on
    unreadable input or lock."""
    snap = collect(data, source, live)
    entries, locked = audit_snapshot(snap, ruleset, lock_path)
    return AuditRun(source=source, snapshot=snap, entries=entries, ruleset=ruleset,
                    lock=locked, lock_path=lock_path)


Loader = Callable[[], AuditRun]
