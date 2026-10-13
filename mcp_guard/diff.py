"""Snapshot diff: how the attack surface changed between two captures.

Pure: two MCPSnapshot in, a SnapshotDiff out. No I/O, no display.

- Servers and tools are matched by name (tools by server, name and rank
  among tools of the same name, like the lock file).
- For a tool present in both, every attribute is compared: description,
  input schema, annotations, other metadata, and what the analyzer makes of
  it (risk and finding categories). JSON values are compared path by path,
  so a changed schema shows the exact property that moved.
- Optionally (`combined`), the `agent-exfiltration-surface` result of both
  snapshots is compared too.

Categories reuse the lock file's: tool-added, tool-removed, tool-changed,
server-added, server-removed, server-changed.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from itertools import islice
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from .analyzer import analyze, known_names, server_entry, tool_entry
from .capabilities import CAPABILITIES, Capability
from .combined import CombinedResult, evaluate
from .models import AuditEntry
from .redact import stored_text
from .rules import DEFAULT_RULESET, RuleSet
from .snapshot import MCPSnapshot, ServerSnapshot, ToolSnapshot

DIFF_FORMAT = "mcp-guard-diff/1"
MAX_PATHS = 100  # path changes kept per field; `truncated` says when more exist
MAX_VALUE_CHARS = 2_000  # bigger old/new values are replaced by their size

Change = Literal["added", "removed", "changed"]
FieldName = Literal["description", "input_schema", "annotations", "metadata", "parse_error",
                    "risk", "spec", "live_status", "live_error", "instructions",
                    "capture_warnings",
                    "resources", "prompts", "mode", "format"]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class PathChange(_Frozen):
    path: str  # JSON path inside the field, e.g. `$.properties.cmd.type`
    op: Change
    old: Any = None
    new: Any = None


class FieldChange(_Frozen):
    field: FieldName
    old: Any = None  # whole values for text fields (description, risk, status)
    new: Any = None
    paths: tuple[PathChange, ...] = ()  # for JSON fields (schema, annotations...)
    truncated: bool = False


class ItemDiff(_Frozen):
    kind: Literal["server", "tool"]
    category: str  # tool-added, tool-removed, tool-changed, server-...
    name: str
    server: str | None = None
    occurrence: int = 0  # 1 for the 2nd tool with the same name on a server
    risk_old: str | None = None
    risk_new: str | None = None
    changes: tuple[FieldChange, ...] = ()
    findings_added: tuple[str, ...] = ()  # finding categories
    findings_removed: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.server} > {self.name}" if self.server else self.name

    @property
    def rug_pull(self) -> bool:
        """A tool that kept its name but changed what it tells the model."""
        return self.category == "tool-changed" and any(
            c.field in ("description", "input_schema", "annotations") for c in self.changes)


class CombinedDiff(_Frozen):
    status_old: str
    status_new: str
    risk_old: str | None = None
    risk_new: str | None = None
    id_old: str | None = None
    id_new: str | None = None
    cut_point_old: str | None = None
    cut_point_new: str | None = None
    tools_added: dict[str, tuple[str, ...]] = {}  # capability -> tool labels
    tools_removed: dict[str, tuple[str, ...]] = {}

    @property
    def changed(self) -> bool:
        return ((self.status_old, self.risk_old, self.id_old, self.cut_point_old)
                != (self.status_new, self.risk_new, self.id_new, self.cut_point_new)
                or any(self.tools_added.values()) or any(self.tools_removed.values()))


class SnapshotDiff(_Frozen):
    format: str = DIFF_FORMAT
    old_digest: str
    new_digest: str
    old_source: str = ""
    new_source: str = ""
    old_captured_at: str = ""
    new_captured_at: str = ""
    old_mode: str = ""
    new_mode: str = ""
    context: tuple[FieldChange, ...] = ()  # snapshot-level: mode, detected format
    items: tuple[ItemDiff, ...] = ()
    combined: CombinedDiff | None = None

    @property
    def identical(self) -> bool:
        """Same content: the digests ignore capture time, path and generator."""
        return self.old_digest == self.new_digest

    @property
    def changed(self) -> bool:
        """Any content difference, even one no item explains (e.g. tools
        reordered): `--exit-code` must never miss a change."""
        return not self.identical or bool(self.combined and self.combined.changed)

    @property
    def unclassified(self) -> bool:
        """The content differs but no server, tool or context change explains it."""
        return not self.identical and not self.items and not self.context

    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for item in self.items:
            result[item.category] = result.get(item.category, 0) + 1
        return result


# --- JSON values ----------------------------------------------------------------


def _clip(value: Any) -> Any:
    """A value small enough for a report; a big subtree becomes a size note."""
    size = len(json.dumps(value, default=str))
    return value if size <= MAX_VALUE_CHARS else f"<{size} chars, not shown>"


def _walk(old: Any, new: Any, path: str) -> Iterator[PathChange]:
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new), key=str):
            child = f"{path}.{key}"
            if key not in old:
                yield PathChange(path=child, op="added", new=_clip(new[key]))
            elif key not in new:
                yield PathChange(path=child, op="removed", old=_clip(old[key]))
            else:
                yield from _walk(old[key], new[key], child)
    elif isinstance(old, list) and isinstance(new, list):
        for index in range(max(len(old), len(new))):
            child = f"{path}[{index}]"
            if index >= len(old):
                yield PathChange(path=child, op="added", new=_clip(new[index]))
            elif index >= len(new):
                yield PathChange(path=child, op="removed", old=_clip(old[index]))
            else:
                yield from _walk(old[index], new[index], child)
    elif old != new:
        yield PathChange(path=path, op="changed", old=_clip(old), new=_clip(new))


def json_changes(old: Any, new: Any, path: str = "$",
                 limit: int | None = None) -> list[PathChange]:
    """Paths where `old` and `new` differ (dict keys and list items are
    walked), at most `limit` of them: the walk stops there."""
    return list(islice(_walk(old, new, path), limit))


def _json_field(field: FieldName, old: Any, new: Any) -> FieldChange | None:
    paths = json_changes(old, new, limit=MAX_PATHS + 1)
    if not paths:
        return None
    return FieldChange(field=field, paths=tuple(paths[:MAX_PATHS]),
                       truncated=len(paths) > MAX_PATHS)


def _value_field(field: FieldName, old: Any, new: Any) -> FieldChange | None:
    return None if old == new else FieldChange(field=field, old=old, new=new)


# --- tools ----------------------------------------------------------------------

ToolKey = tuple[str | None, str, int]
_Known = tuple[frozenset[str], frozenset[str]]  # tool names in the old and new snapshots


def _keyed(tools: list[ToolSnapshot]) -> dict[ToolKey, ToolSnapshot]:
    keyed: dict[ToolKey, ToolSnapshot] = {}
    seen: dict[tuple[str | None, str], int] = {}
    for tool in tools:
        rank = seen.get((tool.server, tool.name), 0)
        seen[(tool.server, tool.name)] = rank + 1
        keyed[(tool.server, tool.name, rank)] = tool
    return keyed


def _categories(entry: AuditEntry) -> set[str]:
    return {f.category for f in entry.findings}


def _tool_fields(old: ToolSnapshot, new: ToolSnapshot) -> list[FieldChange]:
    candidates = (
        _value_field("description", old.description, new.description),
        _json_field("input_schema", old.input_schema, new.input_schema),
        _json_field("annotations", old.annotations or {}, new.annotations or {}),
        _json_field("metadata", old.metadata, new.metadata),
        _value_field("parse_error", old.parse_error, new.parse_error),
    )
    return [c for c in candidates if c is not None]


def _tool_diff(key: ToolKey, old: ToolSnapshot | None, new: ToolSnapshot | None,
               ruleset: RuleSet, known: _Known) -> ItemDiff | None:
    server, name, rank = key
    before = tool_entry(old, ruleset, known[0]) if old else None
    after = tool_entry(new, ruleset, known[1]) if new else None
    changes = _tool_fields(old, new) if old and new else []
    risk = _value_field("risk", before.risk.name if before else None,
                        after.risk.name if after else None)
    if old and new and risk:
        changes.append(risk)
    old_cats = _categories(before) if before else set()
    new_cats = _categories(after) if after else set()
    if old and new and not changes and old_cats == new_cats:
        return None
    category = "tool-added" if old is None else "tool-removed" if new is None else "tool-changed"
    return ItemDiff(kind="tool", category=category, name=name, server=server, occurrence=rank,
                    risk_old=before.risk.name if before else None,
                    risk_new=after.risk.name if after else None, changes=tuple(changes),
                    findings_added=tuple(sorted(new_cats - old_cats)),
                    findings_removed=tuple(sorted(old_cats - new_cats)))


def _tools(old: MCPSnapshot, new: MCPSnapshot, ruleset: RuleSet) -> list[ItemDiff]:
    before, after = _keyed(list(old.all_tools())), _keyed(list(new.all_tools()))
    order = list(before) + [k for k in after if k not in before]
    known = (known_names(old), known_names(new))
    diffs = [_tool_diff(k, before.get(k), after.get(k), ruleset, known) for k in order]
    return [d for d in diffs if d is not None]


# --- servers --------------------------------------------------------------------


def _spec(server: ServerSnapshot) -> Any:
    """The spec as stored: redacted, so both sides compare the same way."""
    return server.model_dump(mode="json")["spec"]


def _by_key(items: tuple[Any, ...], key: str) -> dict[str, Any]:
    """Resources (by uri) or prompts (by name) with all their content, so a
    changed prompt description shows as `$.<name>.description`."""
    return {str(getattr(item, key)): item.model_dump(mode="json", exclude={"provenance"})
            for item in items}


def _stored(text: str | None) -> str | None:
    """Instructions as a snapshot file stores them (URL credentials removed)."""
    return stored_text(text) if text is not None else None


def _server_fields(old: ServerSnapshot, new: ServerSnapshot) -> list[FieldChange]:
    candidates = (
        _json_field("spec", _spec(old), _spec(new)),
        _value_field("parse_error", old.parse_error, new.parse_error),
        _value_field("live_status", old.live_status, new.live_status),
        _value_field("live_error", old.live_error, new.live_error),
        _value_field("instructions", _stored(old.instructions), _stored(new.instructions)),
        _json_field("capture_warnings", list(old.capture_warnings),
                    list(new.capture_warnings)),
        _json_field("resources", _by_key(old.resources, "uri"), _by_key(new.resources, "uri")),
        _json_field("prompts", _by_key(old.prompts, "name"), _by_key(new.prompts, "name")),
    )
    return [c for c in candidates if c is not None]


def _server_diff(name: str, old: ServerSnapshot | None, new: ServerSnapshot | None,
                 ruleset: RuleSet, known: _Known) -> ItemDiff | None:
    before = server_entry(old, ruleset, known[0]) if old else None
    after = server_entry(new, ruleset, known[1]) if new else None
    changes = _server_fields(old, new) if old and new else []
    risk = _value_field("risk", before.risk.name if before else None,
                        after.risk.name if after else None)
    if old and new and risk:
        changes.append(risk)
    old_cats = _categories(before) if before else set()
    new_cats = _categories(after) if after else set()
    if old and new and not changes and old_cats == new_cats:
        return None
    category = ("server-added" if old is None else "server-removed" if new is None
                else "server-changed")
    return ItemDiff(kind="server", category=category, name=name,
                    risk_old=before.risk.name if before else None,
                    risk_new=after.risk.name if after else None, changes=tuple(changes),
                    findings_added=tuple(sorted(new_cats - old_cats)),
                    findings_removed=tuple(sorted(old_cats - new_cats)))


def _servers(old: MCPSnapshot, new: MCPSnapshot, ruleset: RuleSet) -> list[ItemDiff]:
    before = {s.name: s for s in old.servers}
    after = {s.name: s for s in new.servers}
    order = list(before) + [n for n in after if n not in before]
    known = (known_names(old), known_names(new))
    diffs = [_server_diff(n, before.get(n), after.get(n), ruleset, known) for n in order]
    return [d for d in diffs if d is not None]


# --- combined -------------------------------------------------------------------


def _labels(result: CombinedResult, capability: Capability) -> set[str]:
    return {t.label for t in result.surface.get(capability, ())}


def _combined(old: MCPSnapshot, new: MCPSnapshot, ruleset: RuleSet) -> CombinedDiff:
    before = evaluate(old, analyze(old, ruleset), ruleset)
    after = evaluate(new, analyze(new, ruleset), ruleset)

    def finding(result: CombinedResult) -> tuple[str | None, str | None]:
        if result.entry is None:
            return None, None
        return result.entry.findings[0].risk.name, result.entry.findings[0].id

    risk_old, id_old = finding(before)
    risk_new, id_new = finding(after)
    return CombinedDiff(
        status_old=before.status, status_new=after.status, risk_old=risk_old,
        risk_new=risk_new, id_old=id_old, id_new=id_new,
        cut_point_old=before.cut_point, cut_point_new=after.cut_point,
        tools_added={c: tuple(sorted(_labels(after, c) - _labels(before, c)))
                     for c in CAPABILITIES},
        tools_removed={c: tuple(sorted(_labels(before, c) - _labels(after, c)))
                       for c in CAPABILITIES})


def diff_snapshots(old: MCPSnapshot, new: MCPSnapshot, ruleset: RuleSet = DEFAULT_RULESET,
                   combined: bool = False) -> SnapshotDiff:
    """Everything that differs between two snapshots, rated with `ruleset`.
    Raises ValueError (pydantic ValidationError) on a snapshot whose tools no
    longer validate, e.g. a hand-edited file."""
    for snap in (old, new):
        names = [s.name for s in snap.servers]
        if len(names) != len(set(names)):
            raise ValueError("the snapshot has several servers with the same name")
    context = [c for c in (_value_field("mode", old.mode, new.mode),
                           _value_field("format", old.format, new.format)) if c]
    return SnapshotDiff(
        context=tuple(context),
        old_digest=old.digest, new_digest=new.digest, old_source=old.source,
        new_source=new.source, old_captured_at=old.captured_at,
        new_captured_at=new.captured_at, old_mode=old.mode, new_mode=new.mode,
        items=tuple(_servers(old, new, ruleset) + _tools(old, new, ruleset)),
        combined=_combined(old, new, ruleset) if combined else None)
