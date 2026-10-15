"""Escaping untrusted text for Rich markup."""

from __future__ import annotations

from rich.markup import escape as _rich_escape

# An empty style tag: renders nothing, and gives a trailing backslash a tag
# to sit in front of.
_GUARD = "[dim][/dim]"


def escape(text: str) -> str:
    """Rich's `escape`, without its trailing-backslash flaw. Rich doubles a
    final backslash so that it cannot escape the tag that may follow; when no
    tag follows, both backslashes are printed (`C:\\` showed as `C:\\\\`).
    Here the trailing backslashes are always doubled and followed by an empty
    tag, before which Rich prints each pair once, whatever comes next."""
    body = text.rstrip("\\")
    trailing = len(text) - len(body)
    if not trailing:
        return _rich_escape(text)
    return _rich_escape(body) + "\\" * (2 * trailing) + _GUARD
