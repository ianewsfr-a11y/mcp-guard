"""MCP Streamable HTTP transport: one POST per message, JSON or SSE answers."""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from ..analysis import safe_url
from ..text import printable
from .protocol import PROTOCOL_VERSION, LiveError, error_name, result_of

MAX_HTTP_BYTES = 10 * 1024 * 1024
_CHUNK = 64 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would replay our headers (Authorization,
    API keys, session id) to whatever host the server points to."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class _Budget:
    """Overall deadline and byte cap for one response, so a server that
    drips bytes or streams forever cannot hang or exhaust memory."""

    def __init__(self, timeout: float) -> None:
        self.deadline = time.monotonic() + timeout
        self.remaining = MAX_HTTP_BYTES

    def spend(self, size: int) -> None:
        self.remaining -= size
        if self.remaining < 0:
            raise LiveError(f"response exceeded {MAX_HTTP_BYTES} bytes")
        if time.monotonic() > self.deadline:
            raise LiveError("response took longer than the timeout")


def _loads_or_none(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _sse_messages(lines: Iterator[bytes], budget: _Budget) -> Iterator[Any]:
    data: list[str] = []
    for raw in lines:
        budget.spend(len(raw))
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif not line and data:
            yield _loads_or_none("\n".join(data))
            data = []
    if data:
        yield _loads_or_none("\n".join(data))


def _json_message(response: http.client.HTTPResponse, budget: _Budget) -> Iterator[Any]:
    chunks = []
    while chunk := response.read(_CHUNK):
        budget.spend(len(chunk))
        chunks.append(chunk)
    yield _loads_or_none(b"".join(chunks).decode("utf-8", errors="replace"))


class HttpTransport:
    def __init__(self, url: str, headers: dict[str, str], timeout: float) -> None:
        if urlsplit(url).scheme not in ("http", "https"):
            raise LiveError(f"unsupported URL scheme: {printable(safe_url(url), 120)}")
        self._url = url
        self._headers = headers
        self._timeout = timeout
        self._next_id = 0
        self._session: str | None = None
        self._version: str | None = None

    def _http_headers(self) -> dict[str, str]:
        headers = {**self._headers, "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        if self._version:
            headers["MCP-Protocol-Version"] = self._version
        return headers

    def _post(self, message: dict[str, Any], method: str,
              request_id: int | None) -> dict[str, Any] | None:
        request = urllib.request.Request(
            self._url, data=json.dumps(message).encode("utf-8"),
            headers=self._http_headers(), method="POST")
        budget = _Budget(self._timeout)
        try:
            with _OPENER.open(request, timeout=self._timeout) as response:
                if method == "initialize":
                    self._session = response.headers.get("Mcp-Session-Id")
                if request_id is None:
                    return None
                content_type = response.headers.get("Content-Type", "")
                candidates = (_sse_messages(iter(response), budget)
                              if content_type.startswith("text/event-stream")
                              else _json_message(response, budget))
                for candidate in candidates:
                    if isinstance(candidate, dict) and candidate.get("id") == request_id:
                        return candidate
        except urllib.error.HTTPError as exc:
            exc.close()
            hint = (" (redirects are not followed)" if 300 <= exc.code < 400
                    else " (legacy HTTP+SSE servers are not supported)")
            raise LiveError(f"HTTP {exc.code} on {method}{hint}") from exc
        except (urllib.error.URLError, OSError, ValueError,
                http.client.HTTPException) as exc:
            raise LiveError(f"cannot reach {printable(safe_url(self._url), 120)}: "
                            f"{error_name(exc)}") from exc
        raise LiveError(f"no JSON-RPC answer to {method}")

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": self._next_id, "method": method,
                   "params": params}
        answer = self._post(message, method, self._next_id)
        if answer is None:
            raise LiveError(f"no JSON-RPC answer to {method}")
        result = result_of(answer, method)
        if method == "initialize":
            version = result.get("protocolVersion")
            self._version = version if isinstance(version, str) else PROTOCOL_VERSION
        return result

    def notify(self, method: str) -> None:
        self._post({"jsonrpc": "2.0", "method": method}, method, None)

    def close(self) -> None:
        if not self._session:
            return
        request = urllib.request.Request(self._url, headers=self._http_headers(),
                                         method="DELETE")
        try:
            _OPENER.open(request, timeout=self._timeout).close()
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
            pass  # session cleanup is best effort
