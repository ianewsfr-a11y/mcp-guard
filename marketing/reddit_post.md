# Reddit post

**Target subreddits:** r/ClaudeAI, r/LocalLLM, r/Python (one sub per day, adapt the first line to each audience; r/Python requires the "Showcase" flair and its template)

---

## Title

Have you actually read your MCP config? I built a tiny CLI that flags shell-exec tools, sudo servers and hardcoded API keys in 10 seconds

## Body

Most of us add MCP servers to Claude Desktop or Cursor by copy-pasting JSON from a README. It works, so nobody re-reads it. But that file can hold a server launched with `sudo`, an API token sitting in plain text in `env`, or a tool whose description says "execute an arbitrary shell command".

None of that is visible when your agent just says "I'll use the tool now".

So I wrote **mcp-guard**, a single-file Python CLI (click + rich + pydantic) that does two things:

**1. `inspect`**: point it at a `claude_desktop_config.json`, a VS Code `mcp.json`, or a `tools/list` dump, and you get a table of every server and tool with a risk level:

- CRITICAL: command execution, root/sudo/privileged
- HIGH: writes/deletes, SQL writes, hardcoded secrets (never printed), servers pointed at `/` or `~`
- MEDIUM: network access, database reads, plain-http remote servers

It matches whole words in names, descriptions and input-schema fields, so `executive_summary` doesn't trigger `exec`. `--json` and `--fail-on high` let you drop it into CI.

**2. `test-injection`**: prints 8 MCP-flavored prompt-injection payloads (tool poisoning, cross-tool shadowing, fake `[SYSTEM]` messages in tool results, URL exfiltration, consent bypass...). Each has a canary string, so you know immediately whether your agent followed it.

What it is **not**: it's a keyword heuristic. It reads what tools *declare*, not what they *do*. It's a 10-second triage, not a sandbox.

Repo (MIT): https://github.com/ianewsfr-a11y/mcp-guard

I'd love feedback on:

- **False positives/negatives** you hit on real servers. Paste a tool definition and I'll add a rule or a test.
- **Config formats** I'm missing (Windsurf? Zed? Continue?)
- **Injection patterns** you've seen in the wild that should be in the kit

And honestly: do you review MCP servers before installing them, or do you trust the README?
