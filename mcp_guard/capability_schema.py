"""Capabilities suggested by a tool's input schema: free path and URL parameters.

A parameter is evidence, never proof. A `config_path` the model can set to
any file is how an agent gets a file read, but only if the tool returns what
it reads. So:

- a parameter constrained by the schema (`enum`, `const`, `pattern`) is
  bounded and suggests nothing: the server says which values it accepts;
- a free path parameter on a tool whose description says it returns
  something it reads ("Read the file at path and return its contents") gives
  `reads_private` with medium confidence;
- a free path parameter otherwise (a tool that only checks the path, "Apply
  settings", a parameter
  described as an identifier or "nothing is read") gives `reads_private` with
  low confidence: reported as uncertain, not counted;
- a parameter that names where to write (`output_path`, or a tool that only
  writes, saves or exports) is not a read;
- a free URL parameter gives `sends_external` (and `ingests_untrusted` when
  the tool fetches it) with medium confidence if the description says the
  tool sends to it or fetches it, low confidence otherwise ("Tell whether a
  string is a valid URL").

Descriptions come from the server: they can lower a tag's confidence but
never remove it. Returns (capability, trigger, confidence) tuples; the
caller turns them into tags.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .capability_words import FETCH_VERBS, SEND_VERBS
from .context import asserted_tokens, effective_tokens, ordered_tokens
from .text import printable

if TYPE_CHECKING:  # capabilities imports this module: types only
    from .capabilities import Capability, Confidence
    from .snapshot import ToolSnapshot

SchemaTag = tuple["Capability", str, "Confidence"]

_PATH_WORDS = frozenset({"path", "paths", "file", "files", "filename", "filepath", "dir",
                         "directory", "folder"})
_URL_WORDS = frozenset({"url", "urls", "uri", "link", "href", "endpoint", "webhook"})
_URL_FORMATS = frozenset({"uri", "url", "iri"})
_OUTPUT_WORDS = frozenset({"output", "dest", "destination", "target", "save", "export"})
_WRITE_VERBS = frozenset({"write", "save", "export", "create", "overwrite"})
# verbs that hand data back to the caller (nouns like "contents" are not enough:
# "Adds file contents to the staging area")
_RETURN_VERBS = frozenset({"read", "return", "show", "cat", "get", "load", "open", "view",
                           "print", "display", "dump", "extract", "fetch"})
_READ_NEGATED = frozenset({"read", "load", "open", "access", "accessed", "opened"})
# a tool that checks a path answers about the file, not with it: "Returns true or false"
_CHECK_VERBS = frozenset({"check", "validate", "verify", "test", "exist", "exists"})
_CONTENT_WORDS = frozenset({"content", "contents", "text", "data", "lines", "body"})
_IDENTIFIER_WORDS = frozenset({"logical", "identifier", "alias"})
_BOUNDING_KEYS = ("enum", "const", "pattern")


def _properties(tool: ToolSnapshot) -> dict[str, dict[str, Any]]:
    properties = tool.input_schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    return {str(k): v for k, v in properties.items() if isinstance(v, dict)}


def _free_string(spec: dict[str, Any]) -> bool:
    kind = spec.get("type")
    stringy = kind in (None, "string") or (isinstance(kind, list) and "string" in kind)
    return stringy and not any(key in spec for key in _BOUNDING_KEYS)


def _description(spec: dict[str, Any]) -> str:
    value = spec.get("description")
    return value if isinstance(value, str) else ""


def _is_path(name: str, spec: dict[str, Any]) -> bool:
    return bool(set(ordered_tokens(name)) & _PATH_WORDS)


def _is_url(name: str, spec: dict[str, Any]) -> bool:
    return bool(set(ordered_tokens(name)) & _URL_WORDS) or spec.get("format") in _URL_FORMATS


def _negates_reading(text: str) -> bool:
    negated = effective_tokens([text], {}) - asserted_tokens([text], {})
    return bool(negated & _READ_NEGATED) or bool(set(ordered_tokens(text)) & _IDENTIFIER_WORDS)


def _path_tag(name: str, spec: dict[str, Any], verbs: frozenset[str]) -> SchemaTag | None:
    shown = printable(name, 40)
    if set(ordered_tokens(name)) & _OUTPUT_WORDS or (verbs & _WRITE_VERBS
                                                      and not verbs & _RETURN_VERBS):
        return None  # where to write: not a read
    checks_only = bool(verbs & _CHECK_VERBS) and not verbs & _CONTENT_WORDS
    if verbs & _RETURN_VERBS and not checks_only and not _negates_reading(_description(spec)):
        return ("reads_private", f"schema: free path parameter `{shown}`, content returned",
                "medium")
    return ("reads_private",
            f"schema: free path parameter `{shown}`; no evidence its content is returned", "low")


def _url_tags(name: str, verbs: frozenset[str]) -> list[SchemaTag]:
    shown = printable(name, 40)
    if verbs & SEND_VERBS or verbs & {"post", "push"}:
        return [("sends_external", f"schema: URL parameter `{shown}`, data sent to it",
                 "medium")]
    if verbs & FETCH_VERBS:
        trigger = f"schema: URL parameter `{shown}`, fetched"
        return [("ingests_untrusted", trigger, "medium"), ("sends_external", trigger, "medium")]
    return [("sends_external", f"schema: free URL parameter `{shown}`; no evidence of a request",
             "low")]


def schema_tags(tool: ToolSnapshot) -> list[SchemaTag]:
    """Tags suggested by the free path and URL parameters of `tool`."""
    verbs = asserted_tokens([tool.description], {}, None, tool.name)
    tags: list[SchemaTag] = []
    for name, spec in _properties(tool).items():
        if not _free_string(spec):
            continue
        if _is_url(name, spec):
            tags += _url_tags(name, verbs)
        elif _is_path(name, spec):
            tag = _path_tag(name, spec, verbs)
            if tag:
                tags.append(tag)
    return tags
