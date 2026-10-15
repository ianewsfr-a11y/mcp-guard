"""Making untrusted strings safe to print."""

from __future__ import annotations

import re

# C0/C1 controls, plus zero-width and bidi characters that can hide or
# reorder text on screen.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")


def printable(text: str, limit: int | None = None) -> str:
    """Replace control characters (newlines, ANSI escapes, bidi overrides,
    zero-width characters...) with `?` so an untrusted string cannot fake,
    hide or erase terminal lines, and optionally cap its length."""
    cleaned = _CONTROL.sub("?", str(text))
    if limit is not None and len(cleaned) > limit:
        return cleaned[: max(limit - 1, 0)] + "…"
    return cleaned


def visible(text: str) -> str:
    """The text without the characters `printable` would replace: two strings
    with the same `visible` form differ only in invisible or control
    characters (a classic way to hide a change)."""
    return _CONTROL.sub("", str(text))


HIDDEN = "[…]"  # what replaces the path, query and fragment of a URL
# The host stops at what may start a path (`\` too: browsers read it as `/`),
# at `%` and `;`; an IPv6 host is bracketed. Whatever follows it is hidden.
_URL = re.compile(r"(?<![A-Za-z+.-])([A-Za-z][A-Za-z0-9+.-]*)://"
                  r"((?:\[[^\]\s/]*\]|[^\s/?#\\\"'<>()\[\]{}|^`%;])*)"
                  r"([/?#\\%;][^\s\"'<>]*)?")
_TRAILING = ".,;:!)]}"  # punctuation after a URL, not part of it


def _origin(match: re.Match[str]) -> str:
    scheme, authority, rest = match.group(1), match.group(2), match.group(3) or ""
    host = authority.rsplit("@", 1)[-1]  # userinfo never shown
    kept = rest[len(rest.rstrip(_TRAILING)):]
    rest = rest.rstrip(_TRAILING)
    hidden = HIDDEN if rest not in ("", "/") else rest
    return f"{scheme}://{host}{hidden}{kept}"


def redact_urls(text: str) -> str:
    """Every URL in `text` reduced to its scheme and host (and port): a
    token in the path, the query or the fragment never reaches a report.
    `https://h.example/mcp/abc?key=x` reads `https://h.example[…]`."""
    return _URL.sub(_origin, text) if "://" in text else text


def escaped(text: str) -> str:
    r"""ASCII-only form where every non-ASCII or control character is written
    as a Python escape (`\u200b`, `\u0435`), so two strings that look
    the same on screen are told apart."""
    return "".join(ch if " " <= ch <= "~" else ch.encode("unicode_escape").decode("ascii")
                   for ch in str(text))
