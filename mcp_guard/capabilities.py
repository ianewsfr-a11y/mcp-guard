"""Capability tags: what a tool gives an agent, independent of risk levels.

Three tags, for the cross-tool `agent-exfiltration-surface` rule:

- `reads_private`: reads the user's data (files, mail, notes, a database, a
  repository...), or runs commands (a shell reads anything);
- `ingests_untrusted`: brings content written by third parties into the
  context (web pages, feeds, inboxes, issues...);
- `sends_external`: can send data out (messages, uploads, posts to a
  service, requests to a URL the model chooses, shell commands).

A tool can carry several tags (`fetch_url`: ingests_untrusted and
sends_external). Each tag keeps its provenance, by priority: a `--rules`
override, then an MCP annotation, then a keyword. Annotations come from the
server, so they can add a tag but never remove one: only the user can. In
the rules file, `remove` wins over `add`, whatever the order.

Keywords are matched with the same contextual exceptions as the risk rules
(so `exceptions:` in a rules file affects both). This is a heuristic on
English text: a hostile server can word its tools to avoid it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .context import effective_tokens

if TYPE_CHECKING:  # rules -> capabilities must not import the snapshot (cycle)
    from .snapshot import ToolSnapshot

Capability = Literal["reads_private", "ingests_untrusted", "sends_external"]
Source = Literal["rule", "annotation", "keyword"]
CAPABILITIES: tuple[Capability, ...] = ("reads_private", "ingests_untrusted", "sends_external")
_PRIORITY: dict[Source, int] = {"rule": 0, "annotation": 1, "keyword": 2}


class CapabilityTag(BaseModel):
    model_config = ConfigDict(frozen=True)

    capability: Capability
    source: Source
    trigger: str  # what set it: `keyword read + file`, `annotation openWorldHint`...


class TaggedTool(BaseModel):
    model_config = ConfigDict(frozen=True)

    server: str | None
    name: str
    tags: tuple[CapabilityTag, ...]
    suppressed: tuple[Capability, ...] = ()  # found, then removed by a --rules override

    @property
    def label(self) -> str:
        return f"{self.server} > {self.name}" if self.server else self.name

    @property
    def capabilities(self) -> frozenset[Capability]:
        return frozenset(t.capability for t in self.tags)

    def tag(self, capability: Capability) -> CapabilityTag | None:
        return next((t for t in self.tags if t.capability == capability), None)


class CapabilityOverride(BaseModel):
    """`--rules` entry: add or remove tags on a tool, or on every tool of a
    server. `tool` alone matches that tool name on any server."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server: str | None = None
    tool: str | None = None
    add: frozenset[Capability] = frozenset()
    remove: frozenset[Capability] = frozenset()

    @field_validator("add", "remove", mode="before")
    @classmethod
    def _as_set(cls, value: object) -> object:
        return frozenset(value) if isinstance(value, (list, tuple, set)) else value

    @model_validator(mode="after")
    def _meaningful(self) -> CapabilityOverride:
        if not self.server and not self.tool:
            raise ValueError("a capability override needs `server`, `tool` or both")
        if not self.add and not self.remove:
            raise ValueError("a capability override needs `add` or `remove`")
        if self.add & self.remove:
            raise ValueError(f"cannot both add and remove {sorted(self.add & self.remove)}")
        return self

    def matches(self, tool: ToolSnapshot) -> bool:
        return ((self.server is None or self.server == tool.server)
                and (self.tool is None or self.tool == tool.name))

    @property
    def target(self) -> str:
        return " > ".join(part for part in (self.server, self.tool) if part)


# --- keyword clauses ------------------------------------------------------------


class Clause(BaseModel):
    """Fires when one `keywords` token is present and, if `requires` is set,
    one of those too (`read` alone says nothing; `read` + `file` does)."""

    model_config = ConfigDict(frozen=True)

    capability: Capability
    keywords: frozenset[str]
    requires: frozenset[str] = Field(default_factory=frozenset)

    def fire(self, tokens: frozenset[str]) -> str | None:
        hits = sorted(self.keywords & tokens)
        context = sorted(self.requires & tokens)
        if not hits or (self.requires and not context):
            return None
        return "keyword " + ", ".join(hits) + (" + " + ", ".join(context) if context else "")


_READ_VERBS = frozenset(
    {"read", "get", "list", "search", "find", "open", "view", "load", "retrieve", "query",
     "select", "lookup", "browse", "export", "show", "fetch", "download"})
_PRIVATE_DATA = frozenset(
    {"file", "directory", "folder", "document", "note", "graph", "entity", "observation",
     "database", "db", "sql", "table", "record", "email", "mail", "inbox", "calendar",
     "contact", "repository", "repo", "drive", "secret", "credential", "password", "history",
     "clipboard", "screenshot", "photo", "customer", "profile"})
_SHELL = frozenset({"shell", "bash", "zsh", "powershell", "pwsh", "terminal", "subprocess",
                    "exec", "execute", "cmd"})
_UNTRUSTED_SOURCES = frozenset(
    {"url", "web", "webpage", "website", "html", "rss", "feed", "browse", "browser", "scrape",
     "crawl", "internet"})
_UNTRUSTED_MESSAGES = frozenset({"email", "mail", "inbox", "issue", "comment", "ticket",
                                 "review", "post"})
_SEND_VERBS = frozenset({"send", "upload", "publish", "reply", "tweet", "webhook", "smtp",
                         "transfer"})
_PUBLISH_VERBS = frozenset({"create", "add", "post", "push", "publish", "append", "write",
                            "comment", "share"})
_REMOTE_TARGETS = frozenset({"issue", "comment", "gist", "pull", "slack", "channel", "discord",
                             "notion", "page", "wiki", "tweet", "remote", "teams"})
_URL_REQUESTS = frozenset({"url", "http", "https", "curl", "wget", "socket", "webhook"})
_REQUEST_VERBS = frozenset({"fetch", "request", "call"})
_WEB_TARGETS = frozenset({"url", "web", "api", "endpoint", "website", "webpage", "http",
                          "https"})

DEFAULT_CLAUSES: tuple[Clause, ...] = (
    Clause(capability="reads_private", keywords=_READ_VERBS, requires=_PRIVATE_DATA),
    Clause(capability="reads_private", keywords=_SHELL),
    Clause(capability="ingests_untrusted", keywords=_UNTRUSTED_SOURCES),
    Clause(capability="ingests_untrusted", keywords=_READ_VERBS, requires=_UNTRUSTED_MESSAGES),
    Clause(capability="sends_external", keywords=_SEND_VERBS),
    Clause(capability="sends_external", keywords=_PUBLISH_VERBS, requires=_REMOTE_TARGETS),
    Clause(capability="sends_external", keywords=_URL_REQUESTS),
    Clause(capability="sends_external", keywords=_REQUEST_VERBS, requires=_WEB_TARGETS),
    Clause(capability="sends_external", keywords=_SHELL),
)
VOCABULARY = frozenset().union(*(c.keywords | c.requires for c in DEFAULT_CLAUSES))


# --- tagging --------------------------------------------------------------------


def _keyword_tags(tool: ToolSnapshot, exceptions: dict[str, frozenset[str]],
                  ) -> list[CapabilityTag]:
    properties = tool.input_schema.get("properties")
    texts = (tool.description, *(properties if isinstance(properties, dict) else ()))
    tokens = effective_tokens(texts, exceptions, VOCABULARY, tool.name)
    tags = []
    for clause in DEFAULT_CLAUSES:
        trigger = clause.fire(tokens)
        if trigger:
            tags.append(CapabilityTag(capability=clause.capability, source="keyword",
                                      trigger=trigger))
    return tags


def _annotation_tags(tool: ToolSnapshot) -> list[CapabilityTag]:
    """`openWorldHint: true`: the tool reads from the outside world. Many
    servers set it on every tool, so it is not taken as an outbound channel."""
    if (tool.annotations or {}).get("openWorldHint") is not True:
        return []
    return [CapabilityTag(capability="ingests_untrusted", source="annotation",
                          trigger="annotation openWorldHint")]


def tag_tool(tool: ToolSnapshot, overrides: tuple[CapabilityOverride, ...] = (),
             exceptions: dict[str, frozenset[str]] | None = None) -> TaggedTool:
    """One tag per capability, from the highest-priority source."""
    found = [*_keyword_tags(tool, exceptions or {}), *_annotation_tags(tool)]
    removed: set[Capability] = set()
    for override in (o for o in overrides if o.matches(tool)):
        found += [CapabilityTag(capability=c, source="rule",
                                trigger=f"rules: add on {override.target}")
                  for c in CAPABILITIES if c in override.add]
        removed |= override.remove
    best: dict[Capability, CapabilityTag] = {}
    for tag in found:
        current = best.get(tag.capability)
        if current is None or _PRIORITY[tag.source] < _PRIORITY[current.source]:
            best[tag.capability] = tag
    tags = tuple(best[c] for c in CAPABILITIES if c in best and c not in removed)
    suppressed = tuple(c for c in CAPABILITIES if c in best and c in removed)
    return TaggedTool(server=tool.server, name=tool.name, tags=tags, suppressed=suppressed)
