"""Splitting a copy of the byte stream into JSON-RPC lines.

The proxy forwards bytes as they arrive; this only looks at a copy. Lines
can come split across reads (a partial line waits for its end) and can be
several megabytes long. A line longer than `MAX_FRAME_BYTES` is not kept for
analysis (it is still forwarded): it is counted in `oversized`.
"""

from __future__ import annotations

MAX_FRAME_BYTES = 16 * 1024 * 1024


class LineSplitter:
    def __init__(self, limit: int = MAX_FRAME_BYTES) -> None:
        self._limit = limit
        self._buffer = bytearray()
        self._skipping = False  # inside an oversized line, until its newline
        self.oversized = 0

    def feed(self, chunk: bytes) -> list[bytes]:
        """The complete lines `chunk` ends, without their newline."""
        lines: list[bytes] = []
        start = 0
        while (end := chunk.find(b"\n", start)) >= 0:
            piece = chunk[start:end]
            if self._skipping:
                self._skipping = False
            elif len(self._buffer) + len(piece) <= self._limit:
                lines.append(bytes(self._buffer) + piece)
            else:
                self.oversized += 1
            self._buffer.clear()
            start = end + 1
        self._keep(chunk[start:])
        return lines

    def _keep(self, rest: bytes) -> None:
        if self._skipping or not rest:
            return
        if len(self._buffer) + len(rest) > self._limit:
            self._buffer.clear()
            self._skipping = True
            self.oversized += 1
        else:
            self._buffer += rest
