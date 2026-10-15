"""MCP tool annotations that make a security claim, and when the tool's own
words contradict them.

A server declares annotations; clients may use them to skip a confirmation
(a "read-only" tool is often auto-approved). So a tool that says
`readOnlyHint: true` while its name or description says it writes or runs
commands is either mislabeled or lying: `annotation-contradiction` (HIGH).

- `readOnlyHint: true` is contradicted by a `write-operation` keyword, or by
  `command-execution` anywhere in the tool's text.
- `destructiveHint: false` only promises additive updates (MCP spec), so
  `create_entities` is consistent with it. It is contradicted by a
  destructive verb (delete, remove, overwrite...) or by `command-execution`.

Write and destructive words count where they describe what the tool does:
its name, its title, or the first word of its description ("Delete a
file.", "Deletes..."). Elsewhere they are often nouns: the official git
server's read-only `git_log` "Shows the commit logs".
"""

from __future__ import annotations

import re
from typing import Any

from .context import word_forms
from .models import Finding, Risk, ToolSpec
from .rules import RuleSet, tokenize

CATEGORY = "annotation-contradiction"
SECURITY_HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
WRITE, COMMANDS = "write-operation", "command-execution"
DESTRUCTIVE_VERBS = frozenset({"delete", "remove", "rm", "unlink", "overwrite", "truncate",
                               "drop", "rmdir", "erase", "purge", "wipe", "destroy"})


def annotations_of(tool: ToolSpec) -> dict[str, Any]:
    annotations = (tool.model_extra or {}).get("annotations")
    return annotations if isinstance(annotations, dict) else {}


_FIRST_WORD = re.compile(r"[A-Za-z]+")


def _titles(tool: ToolSpec, annotations: dict[str, Any]) -> list[str]:
    """Title at the top level or in the annotations."""
    titles = [(tool.model_extra or {}).get("title"), annotations.get("title")]
    return [t for t in titles if isinstance(t, str)]


def _strong_tokens(tool: ToolSpec, annotations: dict[str, Any],
                   vocabulary: frozenset[str]) -> set[str]:
    """Word forms in the name, the title and the description's first word."""
    first = _FIRST_WORD.search(tool.description)
    texts = [tool.name, *_titles(tool, annotations), first.group(0) if first else ""]
    return {form for token in tokenize(*texts) for form in word_forms(token, vocabulary)}


def _action_words(tool: ToolSpec, annotations: dict[str, Any], ruleset: RuleSet) -> set[str]:
    """Write keywords that survive the contextual exceptions on the whole text
    ("Add two numbers" excuses "add"), kept only when they sit in the name,
    the title or the first word of the description."""
    texts = [tool.description, *_titles(tool, annotations)]
    hits = {f.category: f.evidence for f in ruleset.match(*texts, name=tool.name)}
    if WRITE not in hits:
        return set()
    return set(hits[WRITE].split(", ")) & _strong_tokens(tool, annotations,
                                                          ruleset.vocabulary())


def _command_words(tool: ToolSpec, annotations: dict[str, Any], ruleset: RuleSet) -> str:
    texts = [tool.description, *_titles(tool, annotations)]
    hits = {f.category: f.evidence for f in ruleset.match(*texts, name=tool.name)}
    return hits.get(COMMANDS, "")


def contradiction(tool: ToolSpec, ruleset: RuleSet) -> Finding | None:
    annotations = annotations_of(tool)
    read_only = annotations.get("readOnlyHint") is True
    not_destructive = annotations.get("destructiveHint") is False
    if not read_only and not not_destructive:
        return None
    writes = _action_words(tool, annotations, ruleset)
    commands = _command_words(tool, annotations, ruleset)
    destructive = writes & DESTRUCTIVE_VERBS
    claims = []
    if read_only and (writes or commands):
        claims.append("readOnlyHint: true")
    if not_destructive and (destructive or commands):
        claims.append("destructiveHint: false")
    if not claims:
        return None
    words = [f"{category} ({', '.join(sorted(found))})" for category, found in (
        (WRITE, writes), (COMMANDS, set(commands.split(", ")) if commands else set()))
        if found]
    return Finding(category=CATEGORY, risk=Risk.HIGH,
                   evidence=f"{' and '.join(claims)}, but the tool says "
                            f"{'; '.join(words)}: a client may auto-approve it",
                   field="annotations")


NON_BOOLEAN = "<non-boolean>"


def security_hints(annotations: Any) -> dict[str, Any]:
    """The security hints a tool declares, as stored in a lock file: booleans
    and null as is, anything else as a marker (a server-controlled string
    could carry anything, and the lock is usually committed). The annotations
    hash still tells two different non-boolean values apart."""
    if not isinstance(annotations, dict):
        return {}
    return {h: v if isinstance(v, bool) or v is None else NON_BOOLEAN
            for h in SECURITY_HINTS if h in annotations  # fixed order, not the server's
            for v in (annotations[h],)}
