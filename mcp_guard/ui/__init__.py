"""Interactive terminal UI (`mcp-guard ui`), built with Textual.

Textual is an optional dependency (the `ui` extra), so CI installs stay
light: nothing outside `app` imports it, and `ensure_available()` checks for
it before the command does any work.

Architecture:

- `mcp_guard.pipeline` runs the audit (config -> live -> lock) exactly as
  `inspect` does and returns an `AuditRun`;
- `model` turns it into groups (servers with their tools), lock statuses and
  Rich renderables for the detail panel; it has no Textual dependency;
- `app` is the Textual application: tree on the left, details on the right,
  key bindings in the footer, a modal for the lock report, and a background
  worker for refresh.
"""

from __future__ import annotations

import importlib
from importlib.metadata import entry_points, packages_distributions

from ..pipeline import AuditRun, Loader

__all__ = ["UIUnavailable", "ensure_available", "install_hint", "run_ui"]


class UIUnavailable(RuntimeError):
    """Textual is not installed."""


_PACKAGE = __name__.split(".")[0]


def _distribution() -> str | None:
    """The installed distribution that provides this package: the owner of
    the `mcp-guard` command, else the one listing the `mcp_guard` files."""
    for entry in entry_points(group="console_scripts", name="mcp-guard"):
        dist = getattr(entry, "dist", None)  # missing on some 3.10 builds
        if entry.value.startswith(_PACKAGE + ".") and dist is not None:
            return str(dist.name)
    names = packages_distributions().get(_PACKAGE) or []
    return names[0] if names else None


def install_hint() -> str:
    """How to add the `ui` extra to the distribution this code came from,
    named as installed (no package name is assumed)."""
    name = _distribution()
    if name is None:
        return ('reinstall mcp-guard with its "ui" extra, '
                'e.g. pip install -e ".[ui]" from a source checkout')
    return (f'pip install "{name}[ui]"   (with pipx: pipx install --force "{name}[ui]", '
            f"or pipx inject {name} textual)")


def ensure_available() -> None:
    """Raise UIUnavailable unless Textual imports; the message says whether
    it is missing (install the extra) or installed but broken."""
    try:
        importlib.import_module("textual")
    except ModuleNotFoundError as exc:
        if exc.name not in (None, "textual"):  # a dependency of Textual is missing
            raise UIUnavailable(f"Textual is installed but cannot load ({exc}). "
                                f"Reinstall it with: {install_hint()}") from exc
        raise UIUnavailable(
            "The terminal UI needs Textual, which is an optional extra. "
            f"Install it with: {install_hint()}") from exc
    except Exception as exc:
        raise UIUnavailable(f"Textual is installed but cannot load ({type(exc).__name__}: "
                            f"{exc}). Reinstall it with: {install_hint()}") from exc


def run_ui(run: AuditRun, loader: Loader | None = None) -> None:
    ensure_available()
    from .app import AuditApp

    AuditApp(run, loader).run()
