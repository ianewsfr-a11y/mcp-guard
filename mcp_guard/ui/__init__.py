"""Interactive terminal UI (`mcp-guard ui`), built with Textual.

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

from ..pipeline import AuditRun, Loader

__all__ = ["run_ui"]


def run_ui(run: AuditRun, loader: Loader | None = None) -> None:
    from .app import AuditApp

    AuditApp(run, loader).run()
