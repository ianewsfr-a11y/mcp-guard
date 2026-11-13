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
override, then an MCP annotation, a keyword, the input schema
(`capability_schema`), and last the server context (a tool that reads back
what another tool of the same server brought in). Annotations come from the
server, so they can add a tag but never remove one: only the user can. In
the rules file, `remove` wins over `add`, whatever the order.

Each tag also has a confidence. `high` comes from the user's rules; `medium`
from the server's own words or schema; `low` when the evidence is weak (a
free path parameter with no sign that its content is returned) or negated
("Makes no network request"). Low-confidence tags are kept apart in
`TaggedTool.uncertain`: reported, never counted by the combined rule. A
negation never removes a tag outright: the words come from the server, and a
server can lie; any non-negated trigger keeps the tag at medium.

Keywords are matched with the same contextual exceptions as the risk rules
(so `exceptions:` in a rules file affects both). This is a heuristic on
English text: a hostile server can word its tools to avoid it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .capability_schema import schema_tags
from .capability_words import FETCH_VERBS, READ_VERBS, SEND_VERBS
from .context import asserted_tokens, effective_tokens

if TYPE_CHECKING:  # rules -> capabilities must not import the snapshot (cycle)
    from .snapshot import ToolSnapshot

Capability = Literal["reads_private", "ingests_untrusted", "sends_external"]
Source = Literal["rule", "annotation", "keyword", "schema", "context"]
Confidence = Literal["high", "medium", "low"]
CAPABILITIES: tuple[Capability, ...] = ("reads_private", "ingests_untrusted", "sends_external")
_PRIORITY: dict[Source, int] = {"rule": 0, "annotation": 1, "keyword": 2, "schema": 3,
                                "context": 4}
_RANK: dict[Confidence, int] = {"high": 0, "medium": 1, "low": 2}


class CapabilityTag(BaseModel):
    model_config = ConfigDict(frozen=True)

    capability: Capability
    source: Source
    trigger: str  # what set it: `keyword read + file`, `annotation openWorldHint`...
    confidence: Confidence = "medium"


class TaggedTool(BaseModel):
    model_config = ConfigDict(frozen=True)

    server: str | None
    name: str
    tags: tuple[CapabilityTag, ...]
    suppressed: tuple[Capability, ...] = ()  # found, then removed by a --rules override
    uncertain: tuple[CapabilityTag, ...] = ()  # low-confidence: reported, not counted

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
    one of those too (`read` alone says nothing; `read` + `file` does), and,
    if `also` is set, one of those as well (`retrieve` + `page` + `address`)."""

    model_config = ConfigDict(frozen=True)

    capability: Capability
    keywords: frozenset[str]
    requires: frozenset[str] = Field(default_factory=frozenset)
    also: frozenset[str] = Field(default_factory=frozenset)

    def fire(self, tokens: frozenset[str]) -> str | None:
        parts = [sorted(self.keywords & tokens)]
        for extra in (self.requires, self.also):
            if extra:
                parts.append(sorted(extra & tokens))
        if not all(parts):
            return None
        return "keyword " + " + ".join(", ".join(p) for p in parts)


_PRIVATE_DATA = frozenset(
    {"file", "directory", "folder", "document", "note", "graph", "entity", "observation",
     "database", "db", "sql", "table", "record", "email", "mail", "inbox", "calendar",
     "contact", "repository", "repo", "drive", "secret", "credential", "password", "history",
     "clipboard", "screenshot", "photo", "customer", "profile"})
_STORED_CONTENT = frozenset({"content", "contents"})
_LOCAL_PLACES = frozenset({"path", "disk", "machine", "filesystem", "computer", "local"})
_SHELL = frozenset({"shell", "bash", "zsh", "powershell", "pwsh", "terminal", "subprocess",
                    "exec", "execute", "cmd"})
# `url` alone is not untrusted content: "the webhook URL", "validate a URL"
_UNTRUSTED_SOURCES = frozenset(
    {"web", "webpage", "website", "html", "rss", "feed", "browse", "browser", "scrape",
     "crawl", "internet", "news", "headline"})
_UNTRUSTED_MESSAGES = frozenset({"email", "mail", "inbox", "issue", "comment", "ticket",
                                 "review", "post"})
_WEB_LOCATORS = frozenset({"url", "urls", "http", "https", "website", "webpage", "link",
                           "links", "site"})
_PAGES = frozenset({"page", "pages"})
_WEB_PLACES = frozenset({"address", "web", "internet", "online", "browser"})
_PUBLISH_VERBS = frozenset({"create", "add", "post", "push", "publish", "append", "write",
                            "comment", "share"})
_REMOTE_TARGETS = frozenset({"issue", "comment", "gist", "pull", "slack", "channel", "discord",
                             "notion", "page", "wiki", "tweet", "remote", "teams"})
_RAW_NETWORK = frozenset({"curl", "wget", "socket", "webhook"})
_REQUEST_VERBS = frozenset({"fetch", "request", "call", "download", "retrieve", "browse",
                            "open", "visit", "crawl", "scrape", "post", "ping"})
_WEB_TARGETS = frozenset({"url", "urls", "web", "api", "endpoint", "website", "webpage", "http",
                          "https", "link", "links", "site"})

DEFAULT_CLAUSES: tuple[Clause, ...] = (
    Clause(capability="reads_private", keywords=READ_VERBS, requires=_PRIVATE_DATA),
    # "Return the contents stored at a path on this machine"; `return` alone is
    # too common ("Returns true or false") to count with the other read verbs
    Clause(capability="reads_private", keywords=READ_VERBS | {"return"},
           requires=_STORED_CONTENT, also=_LOCAL_PLACES),
    Clause(capability="reads_private", keywords=_SHELL),
    Clause(capability="ingests_untrusted", keywords=_UNTRUSTED_SOURCES),
    Clause(capability="ingests_untrusted", keywords=READ_VERBS, requires=_UNTRUSTED_MESSAGES),
    Clause(capability="ingests_untrusted", keywords=FETCH_VERBS, requires=_WEB_LOCATORS),
    Clause(capability="ingests_untrusted", keywords=FETCH_VERBS, requires=_PAGES,
           also=_WEB_PLACES),
    Clause(capability="sends_external", keywords=SEND_VERBS),
    Clause(capability="sends_external", keywords=_PUBLISH_VERBS, requires=_REMOTE_TARGETS),
    Clause(capability="sends_external", keywords=_RAW_NETWORK),
    Clause(capability="sends_external", keywords=_REQUEST_VERBS, requires=_WEB_TARGETS),
    Clause(capability="sends_external", keywords=_REQUEST_VERBS, requires=_PAGES,
           also=_WEB_PLACES),
    Clause(capability="sends_external", keywords=_SHELL),
)
VOCABULARY = frozenset().union(*(c.keywords | c.requires | c.also for c in DEFAULT_CLAUSES))


# --- tagging --------------------------------------------------------------------


def _keyword_tags(tool: ToolSnapshot, exceptions: dict[str, frozenset[str]],
                  ) -> list[CapabilityTag]:
    """Medium confidence when a clause fires on words the description asserts;
    low when it only fires on negated ones ("makes no network request")."""
    properties = tool.input_schema.get("properties")
    texts = (tool.description, *(properties if isinstance(properties, dict) else ()))
    tokens = effective_tokens(texts, exceptions, VOCABULARY, tool.name)
    asserted = asserted_tokens(texts, exceptions, VOCABULARY, tool.name)
    tags = []
    for clause in DEFAULT_CLAUSES:
        trigger = clause.fire(asserted)
        if trigger:
            tags.append(CapabilityTag(capability=clause.capability, source="keyword",
                                      trigger=trigger))
            continue
        trigger = clause.fire(tokens)
        if trigger:
            tags.append(CapabilityTag(capability=clause.capability, source="keyword",
                                      trigger=trigger + " (negated in the description)",
                                      confidence="low"))
    return tags


def _annotation_tags(tool: ToolSnapshot) -> list[CapabilityTag]:
    """`openWorldHint: true`: the tool reads from the outside world. Many
    servers set it on every tool, so it is not taken as an outbound channel."""
    if (tool.annotations or {}).get("openWorldHint") is not True:
        return []
    return [CapabilityTag(capability="ingests_untrusted", source="annotation",
                          trigger="annotation openWorldHint")]


def _best(tags: list[CapabilityTag]) -> dict[Capability, CapabilityTag]:
    """One tag per capability: highest confidence, then highest-priority source."""
    best: dict[Capability, CapabilityTag] = {}
    for tag in tags:
        current = best.get(tag.capability)
        if current is None or ((_RANK[tag.confidence], _PRIORITY[tag.source])
                               < (_RANK[current.confidence], _PRIORITY[current.source])):
            best[tag.capability] = tag
    return best


def _split(tool: ToolSnapshot, found: list[CapabilityTag],
           removed: set[Capability]) -> TaggedTool:
    best = _best(found)
    kept = [best[c] for c in CAPABILITIES if c in best and c not in removed]
    return TaggedTool(server=tool.server, name=tool.name,
                      tags=tuple(t for t in kept if t.confidence != "low"),
                      uncertain=tuple(t for t in kept if t.confidence == "low"),
                      suppressed=tuple(c for c in CAPABILITIES if c in best and c in removed))


def removed_by_rules(tool: ToolSnapshot,
                     overrides: tuple[CapabilityOverride, ...]) -> set[Capability]:
    removed: set[Capability] = set()
    for override in (o for o in overrides if o.matches(tool)):
        removed |= override.remove
    return removed


def tag_tool(tool: ToolSnapshot, overrides: tuple[CapabilityOverride, ...] = (),
             exceptions: dict[str, frozenset[str]] | None = None) -> TaggedTool:
    """One tag per capability, from the most confident, highest-priority source."""
    from_schema = [CapabilityTag(capability=c, source="schema", trigger=t, confidence=k)
                   for c, t, k in schema_tags(tool)]
    found = [*_keyword_tags(tool, exceptions or {}), *_annotation_tags(tool), *from_schema]
    for override in (o for o in overrides if o.matches(tool)):
        found += [CapabilityTag(capability=c, source="rule", confidence="high",
                                trigger=f"rules: add on {override.target}")
                  for c in CAPABILITIES if c in override.add]
    return _split(tool, found, removed_by_rules(tool, overrides))


# --- server context -------------------------------------------------------------

STORED_CONTENT = frozenset(
    {"item", "items", "entry", "entries", "article", "articles", "digest", "digests",
     "summary", "summaries", "post", "posts", "message", "messages", "story", "stories",
     "headline", "headlines", "comment", "comments"})


def with_server_context(tagged: list[TaggedTool], tools: list[ToolSnapshot],
                        overrides: tuple[CapabilityOverride, ...] = ()) -> list[TaggedTool]:
    """A tool that reads back stored items, articles, digests... from a server
    that brings third-party content in carries that content too: "Read the
    items of a run stage" on an aggregator whose other tool fetches feeds.
    Medium confidence, source `context`; only from tags that are not
    themselves derived, and never against a `remove` rule."""
    sources: dict[str | None, str] = {}
    for item in tagged:
        tag = item.tag("ingests_untrusted")
        if tag and tag.source != "context":
            sources.setdefault(item.server, item.name)
    if not sources:
        return tagged
    by_key = {(t.server, t.name): t for t in tools}
    result = []
    for item in tagged:
        tool = by_key.get((item.server, item.name))
        origin = sources.get(item.server)
        if (tool is None or origin is None or origin == item.name
                or "ingests_untrusted" in item.capabilities
                or "ingests_untrusted" in removed_by_rules(tool, overrides)
                or not _reads_stored_content(tool)):
            result.append(item)
            continue
        derived = CapabilityTag(capability="ingests_untrusted", source="context",
                                trigger=f"context: reads back what {origin} brings in")
        result.append(item.model_copy(update={
            "tags": tuple(sorted((*item.tags, derived),
                                 key=lambda t: CAPABILITIES.index(t.capability))),
            "uncertain": tuple(t for t in item.uncertain
                               if t.capability != "ingests_untrusted")}))
    return result


def _reads_stored_content(tool: ToolSnapshot) -> bool:
    tokens = asserted_tokens([tool.description], {}, None, tool.name)
    return bool(tokens & READ_VERBS) and bool(tokens & STORED_CONTENT)
