"""What the proxy looks at, on a copy of the traffic, in its own thread.

- `tools/list`: requests are tracked by id (pages by cursor); when the last
  page arrives, the full list is compared with the lock and with the
  previous list of the session, and analyzed (poisoning, contradictory
  annotations).
- `notifications/tools/list_changed`, with or without the 2026-07-28
  `io.modelcontextprotocol/subscriptionId`: noted; the next list shows what
  changed.
- Server identity, from `initialize`, `server/discover` or the `_meta` of
  any result: compared with the lock and within the session. There is no
  need to wait for an `initialize` (the 2026-07-28 revision has none). A
  change (`identity-changed`) re-arms the session: the next complete tool
  list (the one carrying the change, if it does) is compared in full with
  the lock and with the last list seen before, and every finding is written
  again, marked "after a server identity change". Poisoning and
  contradiction findings are written again once too, then deduplicated.
- `resultType` (2026-07-28) may be present or absent; nothing is rewritten.

Lines are queued without blocking: a full queue (1000 lines or 64 MB)
drops lines for analysis (they are still forwarded) and counts them.

Only a message without `method` that has a `result` or an `error` is taken
as an answer: a server request reusing the id of a pending `tools/list`
(`{"id": 2, "method": "ping"}`) must not hide the real answer.
"""

from __future__ import annotations

import json
import queue
import threading
from collections.abc import Callable
from typing import Any

from ..analysis import analyze_tool
from ..annotations import CATEGORY as CONTRADICTION
from ..collector import tool_snapshot
from ..identity import ServerIdentity, identity_findings, identity_from, merged
from ..lock import ToolPrint, diff_tools, tool_prints
from ..models import Finding, Risk
from ..rules import DEFAULT_RULESET
from .context import LockContext
from .recorder import Recorder

CLIENT, SERVER = "client->server", "server->client"
QUEUE_SIZE = 1000
QUEUE_BYTES = 64 * 1024 * 1024  # lines waiting for analysis, all together
MAX_PENDING = 1000  # requests awaiting an answer
MAX_LISTED = 2_000  # tools accumulated over the pages of one list
_TRACKED = frozenset({"tools/list", "initialize", "server/discover"})
_LIST_CHANGED = "notifications/tools/list_changed"

Report = Callable[[str, str, Finding], None]  # (where, label, finding)
Note = Callable[[str], None]


def _key(ident: Any) -> str:
    return json.dumps(ident, sort_keys=True)


def _messages(line: bytes) -> list[dict[str, Any]] | None:
    """The JSON-RPC message(s) in a line (a batch is a list); None if not JSON."""
    try:
        data = json.loads(line.decode("utf-8"))
    except (ValueError, RecursionError):  # not UTF-8, not JSON, nested too deep
        return None
    items = data if isinstance(data, list) else [data]
    return [m for m in items if isinstance(m, dict)]


def _texts(tools: tuple[Any, ...], server: str | None,
           ) -> dict[tuple[str | None, str, int], str]:
    """Descriptions keyed like the lock: (server, name, rank among same names)."""
    texts: dict[tuple[str | None, str, int], str] = {}
    seen: dict[str, int] = {}
    for tool in tools:
        if tool.parse_error is not None:
            continue
        rank = seen.get(tool.name, 0)
        seen[tool.name] = rank + 1
        texts[(server, tool.name, rank)] = tool.description
    return texts


class Session:
    """State of one proxied session. Not thread-safe: the inspector thread owns it."""

    def __init__(self, context: LockContext, report: Report, note: Note) -> None:
        self.context = context
        self._report = report
        self._note = note
        self._pending: dict[str, str] = {}
        self._pages: list[Any] = []
        self._previous: list[ToolPrint] | None = None
        self._identity: ServerIdentity | None = None
        self._announced = False
        self._rearmed = False  # an identity change: the next comparison is complete
        self.listings = 0

    @property
    def server(self) -> str:
        return self.context.server or "server"

    def client(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        if method in _TRACKED and "id" in message:
            if len(self._pending) >= MAX_PENDING:
                self._pending.pop(next(iter(self._pending)))  # oldest, never answered
            self._pending[_key(message["id"])] = str(method)
            params = message.get("params")
            if method == "tools/list" and not (isinstance(params, dict) and params.get("cursor")):
                self._pages = []

    def server_message(self, message: dict[str, Any]) -> None:
        if message.get("method") == _LIST_CHANGED:
            self._list_changed(message)
            return
        if "id" not in message or "method" in message:
            return  # a notification, or a request from the server
        if "result" not in message and "error" not in message:
            return
        kind = self._pending.pop(_key(message["id"]), None)
        result = message.get("result")
        self._observe_identity(result, kind)
        if kind == "tools/list" and isinstance(result, dict):
            self._page(result)

    def _list_changed(self, message: dict[str, Any]) -> None:
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        subscription = meta.get("io.modelcontextprotocol/subscriptionId") \
            if isinstance(meta, dict) else None
        via = f" (subscription {subscription})" if subscription is not None else ""
        self._note(f"the server says its tools changed{via}; the next tools/list "
                   "will show what changed")
        self._announced = True

    def _observe_identity(self, result: Any, kind: str | None) -> None:
        if kind == "server/discover" and isinstance(result, dict) and "tools" in result:
            self._note("server/discover carried a `tools` array (non-standard shape): "
                       "logged, not used; tools/list remains the source of tools")
        seen = identity_from(result)
        if seen is None:
            return
        current = merged(self._identity, seen)
        if current is None:
            return
        if self._identity is not None:
            changes = identity_findings(self._identity, current, "during this session")
            where = "session"
        else:
            reference = self.context.identity
            changes = identity_findings(reference, current, "since the lock") \
                if reference is not None else []
            where = "lock"
        for finding in changes:
            self._report(where, self.server, finding)
        self._rearmed = self._rearmed or bool(changes)
        self._identity = current

    def _page(self, result: dict[str, Any]) -> None:
        tools = result.get("tools")
        if not isinstance(tools, list):
            self._pages = []
            self._note("a tools/list answer has no `tools` array (non-standard shape): "
                       "not compared")
            return
        room = MAX_LISTED - len(self._pages)
        if len(tools) > room:
            self._note(f"tools/list longer than {MAX_LISTED} tools: the rest is not inspected")
        self._pages += tools[:max(room, 0)]
        if result.get("nextCursor"):
            return  # more pages to come
        listing, self._pages = self._pages, []
        self.compare(listing)

    def compare(self, raw_tools: list[Any]) -> None:
        """A complete tool list: analyze it, compare it with the lock and with
        the previous list of this session."""
        self.listings += 1
        server = self.context.server
        tools = tuple(tool_snapshot(raw, i, "live", server) for i, raw in enumerate(raw_tools))
        known = frozenset(t.name for t in tools)
        contradicted: set[str] = set()
        where = "analysis-rearmed" if self._rearmed else "analysis"  # written again once
        for tool in tools:
            if tool.parse_error is None:
                try:
                    contradicted |= self._analyze(tool.spec(), known, where)
                except RecursionError:
                    continue  # reported by the comparison below
        try:
            self._diff(tools, server, frozenset(contradicted))
        except RecursionError:
            self._report("analysis", self.server, Finding(
                category="tool-changed", risk=Risk.HIGH,
                evidence="a tool list nested too deeply to be fingerprinted: it was not "
                         "compared with the lock or the previous list", field="tools/list"))

    def _diff(self, tools: tuple[Any, ...], server: str | None,
              contradicted: frozenset[str]) -> None:
        texts = _texts(tools, server)
        suffix = "-rearmed" if self._rearmed else ""  # spent only once the diff succeeds
        if self.context.tools is not None:
            prints = tool_prints(tools, server, self.context.version)
            for label, finding in diff_tools(list(self.context.tools), prints, texts,
                                             contradicted):
                self._report("lock" + suffix, label, finding)
        current = tool_prints(tools, server)
        if self._previous is not None:
            for label, finding in diff_tools(self._previous, current, texts, contradicted):
                self._report("session" + suffix, label, finding)
        elif self._announced:
            self._note("tools changed before any earlier list was seen in this session")
        self._previous, self._announced, self._rearmed = current, False, False

    def _analyze(self, spec: Any, known: frozenset[str], where: str = "analysis") -> set[str]:
        """Report poisoning and contradictions; the label, if it contradicts itself."""
        entry = analyze_tool(spec, DEFAULT_RULESET, self.context.server, known)
        contradicted = set()
        for finding in entry.findings:
            if finding.category.endswith("poisoning") or finding.category == CONTRADICTION:
                self._report(where, entry.label, finding)
            if finding.category == CONTRADICTION:
                contradicted.add(entry.label)
        return contradicted


class Inspector:
    """Runs a Session in its own thread; `offer` never blocks.

    `session` may be a factory: it then runs in the inspector thread, so that
    reading the lock and hashing the pinned files never delays the server's
    start (lines wait in the queue meanwhile)."""

    def __init__(self, session: Session | Callable[[], Session], recorder: Recorder | None,
                 note: Note) -> None:
        self._factory = session if not isinstance(session, Session) else None
        self.session = session if isinstance(session, Session) else None
        self._recorder = recorder
        self._note = note
        self._queue: queue.Queue[tuple[str, bytes]] = queue.Queue(maxsize=QUEUE_SIZE)
        self._bytes = 0
        self._count = threading.Lock()
        self._stopping = threading.Event()
        self.dropped = 0
        self._warned = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def offer(self, direction: str, line: bytes) -> None:
        with self._count:
            if self._bytes + len(line) > QUEUE_BYTES:
                self.dropped += 1
                return
            try:
                self._queue.put_nowait((direction, line))
            except queue.Full:
                self.dropped += 1
                return
            self._bytes += len(line)

    def notify(self, text: str) -> None:
        """A note from the traffic threads, written by this thread: writing to
        stderr can block, the traffic must not."""
        self.offer("note", text.encode("utf-8", errors="replace"))

    def _start_session(self, factory: Callable[[], Session]) -> Session:
        try:
            return factory()
        except Exception as exc:  # fail-open  # noqa: BLE001
            self._note(f"inspection disabled (internal error: {type(exc).__name__}); "
                       "traffic is not affected")
            return Session(LockContext(), lambda *_: None, self._note)

    def _run(self) -> None:
        if self.session is None and self._factory is not None:
            self.session = self._start_session(self._factory)
        while True:
            try:
                direction, line = self._queue.get(timeout=0.05)
            except queue.Empty:
                if self._stopping.is_set():
                    return
                continue
            with self._count:
                self._bytes -= len(line)
            self._warn_dropped()
            try:
                self.handle(direction, line)
            except Exception as exc:  # fail-open: report, keep going  # noqa: BLE001
                self._note(f"internal error while inspecting a message ({type(exc).__name__}: "
                           f"{exc}); traffic is not affected")

    def _warn_dropped(self) -> None:
        """Said as soon as it happens, not only at exit."""
        if self.dropped and not self._warned:
            self._warned = True
            self._note("messages are arriving faster than they can be inspected: some are "
                       "forwarded without inspection, changes can be missed")

    def handle(self, direction: str, line: bytes) -> None:
        if direction == "note":
            self._note(line.decode("utf-8", errors="replace"))
            return
        assert self.session is not None  # nosec B101
        messages = _messages(line)
        if self._recorder is not None:
            single = messages[0] if messages and len(messages) == 1 else messages
            self._recorder.record(direction, line, single)
        if messages is None:
            if line.strip():
                self._note(f"a {direction} line is not JSON ({len(line)} bytes): forwarded "
                           "as is, not inspected")
            return
        for message in messages:
            if direction == CLIENT:
                self.session.client(message)
            else:
                self.session.server_message(message)

    def stop(self, timeout: float = 5.0) -> None:
        """Analyze what is queued, for at most `timeout` seconds."""
        self._stopping.set()
        self._thread.join(timeout)
