"""One audit run, shared by `inspect` and `ui`: config -> live -> lock."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analysis import audit
from .formats import Discovered, discover
from .live import LiveError, LiveResults, merge_live_results
from .lock import LockFile, compare, read_lock, snapshot
from .models import AuditEntry
from .rules import RuleSet


@dataclass(frozen=True)
class AuditRun:
    source: str
    found: Discovered
    entries: tuple[AuditEntry, ...]
    ruleset: RuleSet
    live: LiveResults | None = None
    lock: LockFile | None = None
    lock_path: Path | None = None
    data: Any = field(default=None, repr=False)


def run_audit(data: Any, source: str, ruleset: RuleSet, live: LiveResults | None = None,
              lock_path: Path | None = None) -> AuditRun:
    """Audit `data`, merge live tools if given, compare with a lock if given.
    Raises ConfigFormatError on unreadable input or lock."""
    found = discover(data)
    entries = audit(data, ruleset)
    if live:
        entries = merge_live_results(entries, live, ruleset)
    locked = None
    if lock_path:
        locked = read_lock(lock_path)
        unreachable = {n for n, r in (live or {}).items() if isinstance(r, LiveError)}
        entries = compare(locked, snapshot(found, live, salt=locked.salt), entries, ruleset,
                          unreachable)
    return AuditRun(source=source, found=found, entries=entries, ruleset=ruleset, live=live,
                    lock=locked, lock_path=lock_path, data=data)


Loader = Callable[[], AuditRun]
