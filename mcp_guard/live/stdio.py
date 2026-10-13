"""stdio transport: newline-delimited JSON-RPC over a subprocess."""

from __future__ import annotations

import json
import os
import queue
import signal

# subprocess is only used by the opt-in, user-confirmed --live mode.
import subprocess  # nosec B404
import sys
import threading
import time
from typing import IO, Any

from ..text import printable
from .protocol import LiveError, error_name, result_of

MAX_LINE_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_SERVER_REQUESTS = 100
_QUEUE_SIZE = 256


def _process_group_options() -> dict[str, Any]:
    """Start the server in its own group so the whole tree (npx -> node,
    cmd /c -> ...) can be killed."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


class StdioTransport:
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
        self._next_id = 0
        self._served = 0
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

    def _next_message(self, deadline: float, method: str) -> dict[str, Any]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LiveError(f"no answer to {method} after {self._timeout:g}s")
            try:
                raw = self._lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if raw is None:
                if self._overflow:
                    raise LiveError(f"server output exceeded {MAX_OUTPUT_BYTES} bytes")
                raise LiveError(f"server exited (code {self._proc.poll()}) "
                                f"before answering {method}")
            try:
                message = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue  # stray log line on stdout
            if isinstance(message, dict):
                return message

    # -- writing ------------------------------------------------------------

    def _send(self, message: dict[str, Any]) -> None:
        if self._proc.stdin is None:
            raise LiveError("server input is not available")
        try:
            self._proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
            self._proc.stdin.flush()
        except OSError as exc:
            raise LiveError(f"server closed its input ({error_name(exc)})") from exc

    def _answer(self, message: dict[str, Any]) -> None:
        self._served += 1
        if self._served > MAX_SERVER_REQUESTS:
            return  # a server flooding us with requests gets no more answers
        if message["method"] == "ping":
            self._send({"jsonrpc": "2.0", "id": message["id"], "result": {}})
        else:
            self._send({"jsonrpc": "2.0", "id": message["id"], "error": {
                "code": -32601, "message": "not supported by mcp-guard"}})

    # -- Transport ----------------------------------------------------------

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method,
                    "params": params})
        deadline = time.monotonic() + self._timeout
        while True:
            message = self._next_message(deadline, method)
            if "method" in message and "id" in message:  # server -> client request
                self._answer(message)
            elif message.get("id") == request_id:
                return result_of(message, method)

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

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
