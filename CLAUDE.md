# mcp-guard: notes for Claude Code

## Git and pull requests

- Never delete a branch while a pull request stacked on it has not been rebased onto `main`. Retarget the stacked PR to `main` first (`gh pr edit <n> --base main`), then merge the base PR with `--delete-branch`. Deleting the base branch first makes GitHub close the stacked PR (this closed #14, replaced by #16).
