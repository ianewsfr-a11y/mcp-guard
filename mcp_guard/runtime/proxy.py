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
_MAX_SEEN = 1000  # lines remembered to write each once
_WHERE = {"lock": "since the lock", "session": "during this session", "analysis": ""}


class Reporter:
    """Writes `mcp-guard:` lines on stderr, once each, from any thread."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream
        self._lock = threading.Lock()
        self._seen: set[str] = set()

    def note(self, text: str) -> None:
        self._write(PREFIX + printable(text, 1000))

    def finding(self, where: str, label: str, finding: Finding) -> None:
        context = f" ({_WHERE[where]})" if _WHERE.get(where) else ""
        self._write(f"{PREFIX}[{finding.risk.name}] {finding.category}{context} "
                    f"{printable(label, 120)}: {printable(finding.evidence, 600)}")

    def _write(self, line: str) -> None:
        with self._lock:
            if line in self._seen:
                return
            if len(self._seen) >= _MAX_SEEN:
                self._seen.clear()  # a line may then repeat; memory stays bounded
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
                                stdout=subprocess.PIPE, stderr=None, bufsize=0)
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


def _relay(child: subprocess.Popen[bytes], inspector: Inspector, stdin_fd: int,
           stdout_fd: int) -> threading.Thread:
    """Start both pumps; the server -> client one is returned, to be joined."""
    assert child.stdin is not None and child.stdout is not None  # nosec B101
    for fd in (stdin_fd, stdout_fd):
        _binary(fd)
    closer = _closer(child.stdin)
    threading.Thread(target=pump, daemon=True, args=(
        stdin_fd, child.stdin.fileno(), CLIENT, inspector, inspector.notify, closer)).start()
    out = threading.Thread(target=pump, daemon=True, args=(
        child.stdout.fileno(), stdout_fd, SERVER, inspector, inspector.notify, closer))
    out.start()  # the client stopped reading: the server's stdin is closed too
    return out


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
    try:
        out = _relay(child, inspector, stdin_fd, stdout_fd)
        previous = _forward_signals(child)
        code = _wait(child)
        out.join(timeout=5)  # flush what the server wrote before exiting
    except BaseException:
        child.kill()  # never leave the server behind
        raise
    finally:
        _restore_signals(previous)
        _stop(inspector, recorder, note)
    return exit_code(code)
