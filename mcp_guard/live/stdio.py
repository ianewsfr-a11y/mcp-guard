"""stdio transport: newline-delimited JSON-RPC over a subprocess."""

from __future__ import annotations

import time
from typing import Any

from .process import JsonLinesProcess
from .protocol import result_of

MAX_SERVER_REQUESTS = 100


class StdioTransport(JsonLinesProcess):
    def __init__(self, executable: str, args: list[str], env: dict[str, str],
                 timeout: float) -> None:
        super().__init__(executable, args, env, timeout)
        self._next_id = 0
        self._served = 0

    def _answer(self, message: dict[str, Any]) -> None:
        self._served += 1
        if self._served > MAX_SERVER_REQUESTS:
            return  # a server flooding us with requests gets no more answers
        if message["method"] == "ping":
            self.send({"jsonrpc": "2.0", "id": message["id"], "result": {}})
        else:
            self.send({"jsonrpc": "2.0", "id": message["id"], "error": {
                "code": -32601, "message": "not supported by mcp-guard"}})

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method,
                   "params": params})
        deadline = time.monotonic() + self._timeout
        while True:
            message = self.next_message(deadline, method)
            if "method" in message and "id" in message:  # server -> client request
                self._answer(message)
            elif message.get("id") == request_id:
                return result_of(message, method)

    def notify(self, method: str) -> None:
        self.send({"jsonrpc": "2.0", "method": method})
