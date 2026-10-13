"""A child process that speaks newline-delimited JSON over stdin/stdout.

Shared by the MCP stdio transport (`--live`) and the agent harness
(`test-injection --run`): output caps, deadlines, and killing the whole
process tree afterwards.
"""

from __future__ import annotations

import json
import os
import queue
import signal

# subprocess is only used by the opt-in, user-confirmed --live / --run modes.
import subprocess  # nosec B404
import sys
import threading
import time
from typing import IO, Any

from ..text import printable
from .protocol import LiveError, error_name

MAX_LINE_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
_QUEUE_SIZE = 256


def _process_group_options() -> dict[str, Any]:
    """Start the child in its own group so the whole tree (npx -> node,
    cmd /c -> ...) can be killed."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


class JsonLinesProcess:
    peer = "server"  # how error messages name the other side

    def __init__(self, executable: str, args: list[str], env: dict[str, str],
                 timeout: float) -> None:
        try:
            self._proc = subprocess.Popen(  # nosec B603
                [executable, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env={**os.environ, **env},
                **_process_group_options())
        except (OSError, ValueError) as exc:
            name = printable(os.path.basename(executable), 80)
            raise LiveError(f"cannot start {name!r}: {error_name(exc)}") from exc
        self._timeout = timeout
        self._overflow = False
        self._lines: queue.Queue[bytes | None] = queue.Queue(maxsize=_QUEUE_SIZE)
        threading.Thread(target=self._pump, daemon=True).start()

    # -- reading ------------------------------------------------------------

    def _pump(self) -> None:
        stdout = self._proc.stdout
        if stdout is not None:
            self._read_lines(stdout)
        self._lines.put(None)

    def _read_lines(self, stdout: IO[bytes]) -> None:
        total = 0
        oversized = False
        while True:
            chunk = stdout.readline(MAX_LINE_BYTES)
            if not chunk:
                return
            total += len(chunk)
            if total > MAX_OUTPUT_BYTES:
                self._overflow = True
                return
            complete = chunk.endswith(b"\n")
            if not oversized and complete:
                self._lines.put(chunk)
            oversized = not complete  # drop the rest of an oversized line

    def next_message(self, deadline: float, waiting_for: str) -> dict[str, Any]:
        """The next JSON object on stdout; non-JSON lines are skipped."""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LiveError(f"no answer to {waiting_for} after {self._timeout:g}s")
            try:
                raw = self._lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if raw is None:
                if self._overflow:
                    raise LiveError(f"{self.peer} output exceeded {MAX_OUTPUT_BYTES} bytes")
                raise LiveError(f"{self.peer} exited (code {self._exit_code()}) "
                                f"before answering {waiting_for}")
            try:
                message = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue  # stray log line on stdout
            if isinstance(message, dict):
                return message

    def _exit_code(self) -> int | str:
        """stdout closes a moment before the process is reaped."""
        try:
            return self._proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            return "unknown"

    # -- writing ------------------------------------------------------------

    def send(self, message: dict[str, Any]) -> None:
        if self._proc.stdin is None:
            raise LiveError(f"{self.peer} input is not available")
        try:
            self._proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
            self._proc.stdin.flush()
        except OSError as exc:
            raise LiveError(f"{self.peer} closed its input ({error_name(exc)})") from exc

    # -- shutdown -----------------------------------------------------------

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        self._kill_tree()
        if self._proc.stdout:
            self._proc.stdout.close()

    def _kill_tree(self) -> None:
        pid = self._proc.pid
        try:
            if sys.platform == "win32":
                if self._proc.poll() is None:
                    taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                            "System32", "taskkill.exe")
                    subprocess.run([taskkill, "/T", "/F", "/PID", str(pid)],  # nosec B603
                                   capture_output=True, check=False, timeout=10)
            else:
                os.killpg(pid, signal.SIGKILL)  # whole session, incl. grandchildren
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            self._proc.kill()
            self._proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
