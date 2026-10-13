"""Making untrusted strings safe to print."""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def printable(text: str, limit: int | None = None) -> str:
    """Replace control characters (newlines, ANSI escapes...) with `?` so an
    untrusted string cannot fake or erase terminal lines, and optionally cap
    its length."""
    cleaned = _CONTROL.sub("?", str(text))
    if limit is not None and len(cleaned) > limit:
        return cleaned[: max(limit - 1, 0)] + "…"
    return cleaned
