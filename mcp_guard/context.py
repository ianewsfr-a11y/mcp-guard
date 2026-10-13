"""Word forms and contextual exceptions for keyword rules.

Two problems with matching raw tokens:

- inflections are missed: "Deletes a file" has `deletes`, not `delete`;
- some keywords are harmless next to certain words: `add` in "Add two
  numbers", `execute` in "Execute a SQL query" (a database read, not a
  shell), `root` in "root directory".

An exception only applies to an occurrence whose *neighbors* (within
`WINDOW` words, in the same text) include a context word. A keyword
survives if any of its occurrences has no such neighbor, so adding
"Supports SQL queries" elsewhere in a description cannot hide "Execute
any command".
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

WINDOW = 2
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
# Plurals that are nouns far more often than verbs in tool docs
# ("blog posts", "latest updates", "list tables").
_NOUN_PLURALS = frozenset({"posts", "updates", "tables", "records", "rights"})


def ordered_tokens(text: str) -> list[str]:
    """Like `rules.tokenize`, but keeps order and repetitions."""
    split = _CAMEL_BOUNDARY.sub(" ", text or "").lower()
    return [w for w in re.split(r"[^a-z0-9]+", split) if w]


def word_forms(token: str, vocabulary: frozenset[str] | None = None) -> set[str]:
    """The token plus its singular for `-s`/`-es`/`-ies` verbs and plurals
    (deletes -> delete, queries -> query). With a vocabulary, only forms in
    it are added. `-ed`/`-ing` are not stemmed: "created date", "saved
    items" are adjectives far more often than actions."""
    forms = {token}
    if token in _NOUN_PLURALS or token.endswith(("ss", "us", "is")):
        return forms
    candidates = []
    if token.endswith("ies"):
        candidates.append(token[:-3] + "y")
    if token.endswith("es"):
        candidates.append(token[:-2])
    if token.endswith("s"):
        candidates.append(token[:-1])
    forms.update(c for c in candidates
                 if len(c) >= 3 and (vocabulary is None or c in vocabulary))
    return forms


_ARITHMETIC = frozenset(
    {"number", "numbers", "two", "sum", "integer", "integers", "math", "arithmetic",
     "digit", "digits", "calculator", "operand", "operands", "numeric", "float", "floats",
     "matrix", "matrices", "vector", "vectors", "days", "hours", "minutes", "seconds"})
_TEXT_OPERATION = frozenset(
    {"string", "strings", "substring", "regex", "character", "characters", "char",
     "chars", "whitespace", "punctuation", "accents", "stopwords"})
_QUERY_LANGUAGE = frozenset({"sql", "query", "queries", "cypher", "graphql"})

# keyword -> neighbor words with which it does not mean what the rule fears
DEFAULT_EXCEPTIONS: dict[str, frozenset[str]] = {
    "add": _ARITHMETIC,
    "remove": _TEXT_OPERATION | {"duplicates", "duplicate", "prefix", "suffix"},
    "replace": _TEXT_OPERATION,
    "truncate": _TEXT_OPERATION | {"words", "text"},
    "move": frozenset({"cursor", "mouse", "pointer", "chess", "piece", "pieces"}),
    "edit": frozenset({"distance"}),
    "exec": _QUERY_LANGUAGE,
    "execute": _QUERY_LANGUAGE,
    "root": frozenset({"cause", "square", "directory", "dir", "folder", "path", "node",
                       "element"}),
    "post": frozenset({"process", "processing", "mortem"}),
    "request": frozenset({"pull", "merge", "feature"}),
    "table": frozenset({"markdown", "html", "csv", "ascii", "format", "formatting"}),
}


def _occurrences(text: str, exceptions: Mapping[str, frozenset[str]],
                 vocabulary: frozenset[str] | None) -> list[tuple[str, bool]]:
    """(form, excused) for every word form in `text`."""
    forms = [word_forms(token, vocabulary) for token in ordered_tokens(text)]
    result = []
    for index, own in enumerate(forms):
        neighbors: set[str] = set()
        for other in range(max(0, index - WINDOW), min(len(forms), index + WINDOW + 1)):
            if other != index:
                neighbors |= forms[other]
        result += [(form, bool(exceptions.get(form, frozenset()) & neighbors))
                   for form in own]
    return result


def effective_tokens(texts: Iterable[str], exceptions: Mapping[str, frozenset[str]],
                     vocabulary: frozenset[str] | None = None,
                     name: str = "") -> frozenset[str]:
    """Every word form found in `texts`, minus the occurrences that an
    adjacent context word excuses. A word in the tool `name` rarely has
    context of its own: it is excused when the name has it, or when every
    use of the word in the texts is excused ("replace_text" described as
    "Replace a substring...")."""
    found: set[str] = set()
    excused_in_texts: dict[str, list[bool]] = {}
    for text in texts:
        for form, excused in _occurrences(text, exceptions, vocabulary):
            excused_in_texts.setdefault(form, []).append(excused)
            if not excused:
                found.add(form)
    for form, excused in _occurrences(name, exceptions, vocabulary):
        uses = excused_in_texts.get(form)
        if not excused and not (uses and all(uses)):
            found.add(form)
    return frozenset(found)
