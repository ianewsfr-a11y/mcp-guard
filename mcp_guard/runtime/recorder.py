"""The proxy's journal: one JSON line per message, written by its own thread.

By default an entry holds the time, the direction, the JSON-RPC method and
id, the size and the SHA-256 of the message, plus what `outcome.details`
reads from it (tool, trace context, outcome): enough to know what happened
without keeping what was said. `--record-bodies` adds the full message (it
can hold secrets the server or the client exchanged; a warning says so).

Nothing here may slow the traffic: entries go through a bounded queue; when
it is full, entries are dropped and counted, never waited for. A journal
that cannot be opened or written is reported once, then recording stops.

The file is created readable by its owner only, and written in ASCII JSON:
a hostile peer cannot put terminal escapes or invalid text in it.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from .outcome import MAX_FIELD as _MAX_FIELD  # method and id come from the peer: capped
from .outcome import Pending, details, peer_id

QUEUE_SIZE = 1000
QUEUE_BYTES = 64 * 1024 * 1024  # bodies waiting to be written, all together

Warn = Callable[[str], None]


def entry(direction: str, line: bytes, message: Any, bodies: bool,
          answers: str | None = None) -> dict[str, Any]:
    method = message.get("method") if isinstance(message, dict) else None
    ident = message.get("id") if isinstance(message, dict) else None
    data: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "direction": direction,
        "method": method[:_MAX_FIELD] if isinstance(method, str) else None,
        "id": peer_id(ident), "size": len(line),
        "sha256": hashlib.sha256(line).hexdigest()}
    if message is None:
        data["note"] = "not JSON"
    if isinstance(message, list):  # a JSON-RPC batch: no details per member
        data["batch"] = len(message)
    try:
        data.update(details(message, direction, answers))
    except Exception:  # fail-open: the base entry is still written  # noqa: BLE001
        data["note"] = "details not recorded (internal error)"
    if bodies:
        data["body"] = line.decode("utf-8", errors="replace")
    return data


class Recorder:
    def __init__(self, handle: IO[str], bodies: bool, warn: Warn) -> None:
        self._handle = handle
        self._bodies = bodies
        self._warn = warn
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=QUEUE_SIZE)
        self.dropped = 0
        self._failed = False
        self._queued = 0  # bytes of bodies waiting
        self._count = threading.Lock()
        self._stopping = threading.Event()
        self._pending = Pending()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    @classmethod
    def open(cls, path: Path, bodies: bool, warn: Warn) -> Recorder | None:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            handle = os.fdopen(fd, "a", encoding="utf-8")
        except OSError as exc:
            warn(f"cannot open the journal {path} ({exc.strerror or exc}): not recording")
            return None
        if bodies:
            warn("--record-bodies: the journal keeps full messages, which can contain "
                 "secrets and personal data; protect it accordingly")
        return cls(handle, bodies, warn)

    def record(self, direction: str, line: bytes, message: Any) -> None:
        """Never blocks: a full queue drops the entry and counts it."""
        if self._failed:
            return
        if self._bodies and self._queued + len(line) > QUEUE_BYTES:
            self.dropped += 1
            return
        try:
            answers = self._pending.answers(direction, message)
            self._queue.put_nowait(entry(direction, line, message, self._bodies, answers))
        except queue.Full:
            self.dropped += 1
            return
        if self._bodies:
            with self._count:
                self._queued += len(line)

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.05)
            except queue.Empty:
                if self._stopping.is_set():
                    return
                continue
            if "body" in item:
                with self._count:
                    self._queued -= item["size"]
            self._write(item)

    def _write(self, item: dict[str, Any]) -> None:
        if self._failed:
            return
        try:
            self._handle.write(json.dumps(item) + "\n")
            self._handle.flush()
        except (OSError, ValueError) as exc:
            self._failed = True
            self._warn(f"cannot write the journal ({exc}): recording stopped")

    def close(self, timeout: float = 2.0, server_exit: int | None = None) -> None:
        """Write what is queued, for at most `timeout` seconds, then the end line
        with the server's exit code (None when it did not start or was killed)."""
        self._stopping.set()
        self._thread.join(timeout)
        if self._thread.is_alive():
            return  # still writing: do not interleave a last line
        self._write({"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                     "event": "end", "dropped": self.dropped, "server_exit": server_exit})
        try:
            self._handle.close()
        except OSError:
            pass
