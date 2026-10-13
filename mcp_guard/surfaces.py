"""The text surfaces of a snapshot that reach the model, as (field path, text).

A client passes these to the model verbatim, so each is a place where a
server can hide instructions:

- tools: name, title, description, string annotations, and in the input and
  output schemas every `description` / `title`, every property name, and
  the string values of `enum`, `const`, `default` and `examples`;
- resources: name, title, description, uri, mimeType;
- prompts: name, title, description, the description of each argument;
- servers: the `instructions` sent at initialization.

Bounded in number and size so a hostile server cannot stall the scan; what
is left out is counted, and reported by the caller (a payload pushed past
the limits must not go unnoticed).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .models import ToolSpec
from .snapshot import PromptSnapshot, ResourceSnapshot

MAX_FIELDS = 500
MAX_TOTAL_CHARS = 400_000

Field = tuple[str, str]  # (path, text)
Fields = tuple[list[Field], int]  # kept fields, number left out
_DOC_KEYS = ("description", "title")
_VALUE_KEYS = ("enum", "const", "default", "examples")


def _strings(value: Any, path: str) -> Iterator[Field]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, list):
        yield from ((f"{path}[{i}]", v) for i, v in enumerate(value) if isinstance(v, str))


def _node_texts(node: dict[str, Any], where: str) -> Iterator[Field]:
    for key, value in node.items():
        if key in _DOC_KEYS and isinstance(value, str):
            yield f"{where}.{key}", value
        elif key in _VALUE_KEYS:
            yield from _strings(value, f"{where}.{key}")
    properties = node.get("properties")
    if isinstance(properties, dict):  # names reach the model too: no_need_to_ask_user
        yield from ((f"{where}.properties.{name}(name)", str(name).replace("_", " "))
                    for name in properties)


def _schema_texts(schema: Any, path: str) -> Iterator[Field]:
    """Text in a JSON schema that the model reads, at any depth."""
    stack: list[tuple[Any, str]] = [(schema, path)]
    while stack:
        node, where = stack.pop()
        if isinstance(node, dict):
            yield from _node_texts(node, where)
            stack.extend((value, f"{where}.{key}") for key, value in node.items()
                         if isinstance(value, (dict, list)) and key not in _VALUE_KEYS)
        elif isinstance(node, list):  # anyOf, oneOf...
            stack.extend((item, f"{where}[{i}]") for i, item in enumerate(node)
                         if isinstance(item, (dict, list)))


def _bounded(fields: Iterator[Field]) -> Fields:
    kept: list[Field] = []
    skipped = 0
    budget = MAX_TOTAL_CHARS
    for path, text in fields:
        if not text:
            continue
        if len(kept) >= MAX_FIELDS or budget <= 0:
            skipped += 1
            continue
        kept.append((path, text[:budget]))
        skipped += len(text) > budget
        budget -= len(kept[-1][1])
    return kept, skipped


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def tool_fields(tool: ToolSpec) -> Fields:
    extra = tool.model_extra or {}
    annotations = extra.get("annotations")

    def walk() -> Iterator[Field]:
        yield "name", tool.name
        yield "title", _text(extra.get("title"))
        yield "description", tool.description
        yield from _schema_texts(tool.inputSchema, "inputSchema")
        yield from _schema_texts(extra.get("outputSchema"), "outputSchema")
        if isinstance(annotations, dict):
            yield from ((f"annotations.{k}", v) for k, v in annotations.items()
                        if isinstance(v, str))
    return _bounded(walk())


def resource_fields(resource: ResourceSnapshot) -> Fields:
    return _bounded(iter([
        ("name", resource.name), ("title", _text(resource.metadata.get("title"))),
        ("description", resource.description), ("uri", resource.uri),
        ("mimeType", resource.mime_type or "")]))


def prompt_fields(prompt: PromptSnapshot) -> Fields:
    def walk() -> Iterator[Field]:
        yield "name", prompt.name
        yield "title", _text(prompt.metadata.get("title"))
        yield "description", prompt.description
        names = [_text(a.get("name")) for a in prompt.arguments]
        for index, argument in enumerate(prompt.arguments):
            name = names[index]
            key = name if name and names.count(name) == 1 else f"[{index}]{name}"
            yield f"arguments.{key}.description", _text(argument.get("description"))
            yield f"arguments.{key}.title", _text(argument.get("title"))
    return _bounded(walk())
