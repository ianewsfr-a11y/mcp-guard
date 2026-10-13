"""One audit run, shared by `inspect` and `ui`:
collect (config, then live) -> snapshot -> analyze -> compare with a lock."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analysis import sort_entries
from .analyzer import analyze
from .collector import Outcome, collect
from .combined import CombinedResult, evaluate
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
    combined: CombinedResult | None = None  # set with --combined


def audit_snapshot(snap: MCPSnapshot, ruleset: RuleSet, lock_path: Path | None = None,
                   ) -> tuple[tuple[AuditEntry, ...], LockFile | None]:
    """Findings for a snapshot, plus lock differences if a lock is given.
    Raises ConfigFormatError on an unreadable or incompatible lock."""
    entries = analyze(snap, ruleset)
    if not lock_path:
        return entries, None
    locked = read_lock(lock_path)
    unreachable = {s.name for s in snap.servers if s.live_status == "failed"}
    return compare(locked, fingerprint(snap, salt=locked.salt), entries, ruleset,
                   unreachable), locked


def run_audit(data: Any, source: str, ruleset: RuleSet,
              live: Mapping[str, Outcome] | None = None,
              lock_path: Path | None = None, combined: bool = False) -> AuditRun:
    """Audit `data` (with live results if given). `combined` adds the
    experimental config-level rule. Raises ConfigFormatError on unreadable
    input or lock."""
    snap = collect(data, source, live)
    entries, locked = audit_snapshot(snap, ruleset, lock_path)
    result = evaluate(snap, entries, ruleset) if combined else None
    if result is not None and result.entry is not None:
        entries = sort_entries([*entries, result.entry], ruleset)
    return AuditRun(source=source, snapshot=snap, entries=entries, ruleset=ruleset,
                    lock=locked, lock_path=lock_path, combined=result)


Loader = Callable[[], AuditRun]
