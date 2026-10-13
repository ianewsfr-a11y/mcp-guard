# mcp-guard: notes for Claude Code

## Context

- v0.8 (`proxy`, command pins, server identity) comes from the r/mcp thread of 2026-10-12. A user wanted a silent change of `readOnlyHint` to become a visible diff. The proxy extends the lock to runtime: it compares what a server declares during a session with the lock and with what the same session saw earlier.
- The MCP revision 2026-07-28 replaces `initialize` with `server/discover`. The source is the specification changelog, relayed by the project owner and not checked here. The assumptions are listed in `mcp_guard/identity.py` and in the CHANGELOG.
- The proxy is fail-open, always: it prevents nothing, it makes changes visible. A blocking mode (`--enforce`) and npm/PyPI package digests are out of scope (see ROADMAP.md).

## Conventions

- Functions under 50 lines, files under 800.
- Pydantic models are immutable (`frozen=True`, `extra="forbid"`). Build new objects instead of mutating them.
- Strict typing: `mypy mcp_guard` must stay clean, on win32 and on linux with Python 3.10.
- Before any commit, `ruff`, `bandit` and `pytest --cov=mcp_guard` must pass. Coverage stays at 97 % or above.
- No network in tests. The fake servers are in `tests/fixtures/`.
- Text printed from server data goes through `text.printable` (no terminal escapes). Secrets never reach a lock, a snapshot or a journal unless `--record-bodies` is set.

## Git and pull requests

- Never delete a branch while a pull request stacked on it has not been rebased onto `main`. Retarget the stacked PR to `main` first (`gh pr edit <n> --base main`), then merge the base PR with `--delete-branch`. Deleting the base branch first makes GitHub close the stacked PR (this closed #14, replaced by #16).
