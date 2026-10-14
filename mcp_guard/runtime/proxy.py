"""`mcp-guard proxy -- <cmd> <args...>`: a pass-through stdio proxy.

The client (Claude Desktop, Cursor...) starts the proxy instead of the
server; the proxy starts the server and copies bytes both ways, unchanged:
no re-serialization, no newline translation (binary mode on Windows),
partial lines and multi-megabyte messages included. The server's stderr is
inherited as is. Closing stdin closes the server's stdin; SIGINT and SIGTERM
are passed on. The proxy exits when the server exits, with its exit code.

A copy of each line goes to the inspector (another thread) and, with
`--record`, to the journal. Findings are written to stderr, prefixed
`mcp-guard:`. Fail-open is absolute: whatever goes wrong on the inspection
side is reported and the traffic goes on.
"""

from __future__ import annotations

import os
import signal
import subprocess  # nosec B404 - runs the server the user put in their client config
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from ..live.launch import resolve_executable
from ..live.protocol import LiveError
from ..models import Finding
from ..text import printable
from . import context as lock_context
from .frames import MAX_FRAME_BYTES, LineSplitter
from .inspector import CLIENT, SERVER, Inspector, Session
from .recorder import Recorder

CHUNK = 64 * 1024
PREFIX = "mcp-guard: "
SERVER_PREFIX = b"server: "  # on each line of the server's stderr
_MAX_SEEN = 1000  # lines remembered, to write each once or to count them
_AFTER = "after a server identity change"
_WHERE = {"lock": "since the lock", "session": "during this session", "analysis": "",
          "lock-rearmed": f"since the lock, {_AFTER}",
          "session-rearmed": f"during this session, {_AFTER}"}
# Recomputed from the same reference on every tools/list: written once. A
# session finding is an event (a flip, then a flip back): always written.
_ONCE = frozenset({"lock", "analysis"})


class Reporter:
    """Writes `mcp-guard:` lines on stderr from any thread. Notes and lock or
    analysis findings are written once; session findings every time, with
    `(occurrence n)` from the second identical one."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream
        self._lock = threading.Lock()
        self._seen: set[str] = set()
        self._counts: dict[str, int] = {}

    def note(self, text: str) -> None:
        self._write(PREFIX + printable(text, 1000))

    def finding(self, where: str, label: str, finding: Finding) -> None:
        context = f" ({_WHERE[where]})" if _WHERE.get(where) else ""
        line = (f"{PREFIX}[{finding.risk.name}] {finding.category}{context} "
                f"{printable(label, 120)}: {printable(finding.evidence, 600)}")
        if where in _ONCE:
            self._write(line)
        else:
            self._write(self._counted(line), once=False)

    def _counted(self, line: str) -> str:
        with self._lock:
            if len(self._counts) >= _MAX_SEEN and line not in self._counts:
                self._counts.clear()  # memory stays bounded; a count may restart
            count = self._counts[line] = self._counts.get(line, 0) + 1
        return line if count == 1 else f"{line} (occurrence {count})"

    def raw(self, data: bytes) -> None:
        """Bytes from the server's stderr, written whole between our lines."""
        with self._lock:
            stream = self._stream or sys.stderr
            try:
                stream.flush()
                buffer = getattr(stream, "buffer", None)
                if buffer is not None:
                    buffer.write(data)
                    buffer.flush()
                else:
                    stream.write(data.decode("utf-8", errors="replace"))
                    stream.flush()
            except (OSError, ValueError):
                pass  # stderr gone: nothing to relay to

    def _write(self, line: str, once: bool = True) -> None:
        with self._lock:
            if once and line in self._seen:
                return
            if once and len(self._seen) >= _MAX_SEEN:
                self._seen.clear()  # a line may then repeat; memory stays bounded
            if once:
                self._seen.add(line)
            try:
                stream = self._stream or sys.stderr
                stream.write(line + "\n")
                stream.flush()
            except (OSError, ValueError):
                pass  # stderr gone: nothing to report to, traffic goes on


def _binary(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(fd, os.O_BINARY)  # no CRLF translation


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _observe(splitter: LineSplitter, chunk: bytes, offer: Callable[[bytes], None],
             note: Callable[[str], None]) -> None:
    """Hand complete lines to the inspector; never raises."""
    try:
        before = splitter.oversized
        for line in splitter.feed(chunk):
            offer(line)
        if splitter.oversized > before:
            note(f"a message over {MAX_FRAME_BYTES // (1024 * 1024)} MB was forwarded "
                 "but not inspected")
    except Exception as exc:  # noqa: BLE001 - fail-open
        note(f"inspection skipped ({type(exc).__name__}); traffic is not affected")


def pump(source: int, target: int, direction: str, inspector: Inspector,
         note: Callable[[str], None], on_end: Callable[[], None]) -> None:
    """Copy `source` to `target` until EOF, unchanged; observe a copy."""
    splitter = LineSplitter()
    try:
        while chunk := os.read(source, CHUNK):
            _write_all(target, chunk)
            _observe(splitter, chunk, lambda line: inspector.offer(direction, line), note)
    except OSError:
        pass  # the other side is gone
    finally:
        on_end()


def prefixed(chunk: bytes, at_start: bool) -> tuple[bytes, bool]:
    """`chunk` with `server: ` at the start of each line (also after a bare
    carriage return, which a terminal uses to overwrite a line), and whether
    the next chunk starts a line. Bytes are otherwise unchanged."""
    out = bytearray()
    for piece in chunk.splitlines(keepends=True):
        if at_start:
            out += SERVER_PREFIX
        out += piece
        at_start = piece.endswith((b"\n", b"\r"))
    return bytes(out), at_start


def relay_stderr(source: int, reporter: Reporter) -> None:
    """The server's stderr, prefixed so that it cannot pass for mcp-guard's."""
    at_start = True
    try:
        while chunk := os.read(source, CHUNK):
            data, at_start = prefixed(chunk, at_start)
            reporter.raw(data)
    except OSError:
        pass  # the server is gone


def _closer(stream: IO[bytes]) -> Callable[[], None]:
    """Closing the server's stdin tells it the client is gone."""
    def close() -> None:
        try:
            stream.close()
        except OSError:
            pass
    return close


def _forward_signals(child: subprocess.Popen[bytes]) -> dict[int, Any]:
    def forward(signum: int, _frame: Any) -> None:
        try:
            if sys.platform == "win32" and signum == signal.SIGTERM:
                child.terminate()
            elif sys.platform != "win32":
                child.send_signal(signum)
            # Windows Ctrl+C: the console already delivers it to the child
        except OSError:
            pass

    previous: dict[int, Any] = {}
    for name in ("SIGINT", "SIGTERM"):
        try:
            number = getattr(signal, name)
            previous[number] = signal.signal(number, forward)
        except (ValueError, OSError, AttributeError):
            pass  # not in the main thread, or not supported here
    return previous


def _restore_signals(previous: dict[int, Any]) -> None:
    for number, handler in previous.items():
        try:
            signal.signal(number, handler)
        except (ValueError, OSError, TypeError):
            pass


def _start(command: str, args: list[str], note: Callable[[str], None],
           ) -> subprocess.Popen[bytes] | None:
    try:
        executable = resolve_executable(command)
        return subprocess.Popen([executable, *args], stdin=subprocess.PIPE,  # nosec B603
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                bufsize=0)
    except (LiveError, OSError, ValueError) as exc:
        note(f"cannot start the server: {printable(str(exc), 300)}")
        return None


def exit_code(returncode: int) -> int:
    """A child killed by a signal (negative code on POSIX) exits as a shell would."""
    return 128 - returncode if returncode < 0 else returncode


def _wait(child: subprocess.Popen[bytes]) -> int:
    """Wait in short steps: on Windows an endless wait would delay the
    signal handlers until the server exits."""
    while True:
        try:
            return child.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            continue


def _session(lock_path: Path | None, command: str, args: list[str], server_name: str | None,
             reporter: Reporter) -> Callable[[], Session]:
    """Built in the inspector thread: reading the lock and hashing the pinned
    files never delays the server's start."""
    def build() -> Session:
        context = lock_context.load(lock_path, command, args, server_name, reporter.note)
        for finding in context.pin_findings:
            reporter.finding("lock", context.server or command, finding)
        return Session(context, reporter.finding, reporter.note)
    return build


def _open_recorder(path: Path | None, bodies: bool, note: Callable[[str], None],
                   ) -> Recorder | None:
    if bodies and path is None:
        note("--record-bodies has no effect without --record")
    try:
        return Recorder.open(path, bodies, note) if path else None
    except Exception as exc:  # fail-open  # noqa: BLE001
        note(f"not recording (internal error: {type(exc).__name__})")
        return None


def _relay(child: subprocess.Popen[bytes], inspector: Inspector, reporter: Reporter,
           stdin_fd: int, stdout_fd: int) -> list[threading.Thread]:
    """Start the pumps; the server -> client ones are returned, to be joined."""
    assert child.stdin is not None and child.stdout is not None  # nosec B101
    assert child.stderr is not None  # nosec B101
    for fd in (stdin_fd, stdout_fd):
        _binary(fd)
    closer = _closer(child.stdin)
    threading.Thread(target=pump, daemon=True, args=(
        stdin_fd, child.stdin.fileno(), CLIENT, inspector, inspector.notify, closer)).start()
    out = threading.Thread(target=pump, daemon=True, args=(
        child.stdout.fileno(), stdout_fd, SERVER, inspector, inspector.notify, closer))
    out.start()  # the client stopped reading: the server's stdin is closed too
    err = threading.Thread(target=relay_stderr, daemon=True,
                           args=(child.stderr.fileno(), reporter))
    err.start()
    return [out, err]


def _finish(child: subprocess.Popen[bytes], readers: list[threading.Thread]) -> None:
    """Flush what the server wrote before exiting, then close its pipes."""
    for reader in readers:
        reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        return  # a grandchild keeps a pipe open: the process exit closes it
    for stream in (child.stdout, child.stderr):
        if stream is not None:
            stream.close()


def _stop(inspector: Inspector, recorder: Recorder | None, note: Callable[[str], None]) -> None:
    inspector.stop()
    if inspector.dropped:
        note(f"{inspector.dropped} message(s) forwarded without inspection (queue full)")
    if recorder is not None:
        recorder.close()


def run_proxy(command: str, args: list[str], lock_path: Path | None = None,
              record_path: Path | None = None, record_bodies: bool = False,
              server_name: str | None = None, stdin_fd: int = 0, stdout_fd: int = 1) -> int:
    reporter = Reporter()
    note = reporter.note
    recorder = _open_recorder(record_path, record_bodies, note)
    inspector = Inspector(_session(lock_path, command, args, server_name, reporter),
                          recorder, note)
    child = _start(command, args, note)
    if child is None:
        _stop(inspector, recorder, note)
        return 127
    previous: dict[int, Any] = {}
    readers: list[threading.Thread] = []
    try:
        readers = _relay(child, inspector, reporter, stdin_fd, stdout_fd)
        previous = _forward_signals(child)
        code = _wait(child)
        _finish(child, readers)
    except BaseException:
        child.kill()  # never leave the server behind
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        _finish(child, readers)
        raise
    finally:
        _restore_signals(previous)
        _stop(inspector, recorder, note)
    return exit_code(code)
