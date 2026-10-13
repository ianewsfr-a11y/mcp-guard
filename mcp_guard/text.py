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
