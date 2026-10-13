# Changelog

## Unreleased

### Added
- **Versioned snapshot** (`mcp_guard/snapshot.py`): `MCPSnapshot` is the captured state of an MCP setup. It holds servers and tools; each tool keeps its raw description, input schema, annotations, other metadata and provenance. With `--live` it also holds the resources and prompts each server declares.
  - `canonical_json()` gives a canonical serialization (sorted keys, compact, ASCII) and `digest` its SHA-256. Both ignore the capture time, the file path and the mcp-guard version.
  - Literal secrets are never serialized, so a snapshot is safe to write to disk:
    - env and header values are redacted, except references;
    - a secret-looking key redacts its whole subtree;
    - URLs anywhere lose their userinfo and their secret query values.
- `--live` pagination refuses a non-string or oversized `nextCursor`. Warnings recorded per server are capped at 20.
- `--live` also calls `resources/list` and `prompts/list` when the server declares them. If they fail, the failure is recorded and the tools are kept. The TUI shows the counts in the server panel, and a tool's annotations next to its input schema.
- Findings have a stable `id` (32 hex characters), included in `--format json`. It is the same value as the SARIF fingerprint, which is unchanged.

### Changed
- Internal architecture split into stages:
  - `collector` turns the config and server answers into an `MCPSnapshot`;
  - `analyzer` turns an `MCPSnapshot` into findings;
  - `renderer` (formerly `render`), the CLI and the TUI only display.
  - Secret redaction moves to `redact`. `inspect`, `lock` and `ui` share this pipeline. Reports are unchanged, and lock files from v0.5 still match.
- New public API: `collect`, `analyze` and `MCPSnapshot` are exported from `mcp_guard`. `audit(data)` is now `analyze(collect(data))`.

## v0.5.1

### Changed
- README: `pip install mcp-guard-audit` is shown next to `pipx`, with how to install pipx when it is missing (common on Windows) and how to upgrade.

## v0.5.0

### Added
- **`mcp-guard ui`**: interactive terminal UI (Textual) on the same audit as `inspect` (`--server`, `--live`, `--lock`, `--rules`).
  - **Left pane:** a tree of servers and tools, riskiest first and colored by risk.
  - **Right pane:** findings, lock status, tool description and input schema (highlighted JSON), and the server launch spec with secrets redacted.
  - **Keys:** Up/Down, Tab, `r` refresh (in the background), `l` lock report, `t` light/dark, `q` quit.
- Refresh with `--live` never starts a server whose spec changed since the user confirmed it.

### Changed
- New runtime dependency: `textual`.
- The audit pipeline (config, then live, then lock) is shared by `inspect` and `ui` (`mcp_guard/pipeline.py`).

## v0.4.0

### Added
- **Rug-pull detection**: `mcp-guard lock CONFIG [--live]` writes `mcp-guard.lock` with SHA-256 fingerprints of every tool (description, input schema, all other fields such as title, annotations, outputSchema) and every server (launch spec; salted HMAC of non-secret env/header/URL-parameter values). `inspect --lock` reports `tool-changed`/`server-changed` (HIGH), `tool-added`/`server-added` (MEDIUM), `tool-removed`/`server-removed` (LOW). Secrets are never stored, not even hashed. Unreachable servers do not produce removals.
- **Automated `test-injection --run`**: mcp-guard plays a hostile MCP server against an agent script over the `mcp-guard-harness/1` JSON-lines protocol. 8 scenarios with honeypot tools. A run FAILs on an echoed canary (also disguised: case, punctuation, reversed, base64, hex), unneeded tool calls, a leaked canary, or any address/host the task did not mention. Exit `1` on FAIL, `2` on ERROR. `--only`, `--timeout`, `--json`, and a confirmation before starting the agent.
- `examples/agents/`: `naive_agent.py` (fails 8/8), `guarded_agent.py` (passes 8/8), `anthropic_agent.py` (tests a real Claude model).
- Rules files accept `exceptions:` (keyword -> adjacent context words).
- **`--server`** for `inspect` and `lock`: audit a server given on the command line (a command or an `http(s)` URL, repeatable) without writing a config file, e.g. `mcp-guard inspect --live --yes --server "npx -y @modelcontextprotocol/server-memory"`.
- README: "Quick Replication" section and PyPI badges.

### Changed
- **Fewer lexical false positives**: keywords are excused only by an adjacent context word (within 2 words): "Add two numbers", "Execute a SQL query", "root directory", "remove duplicates", "markdown table" no longer raise write/exec/privileged/database findings. A context word elsewhere excuses nothing, so attackers cannot hide "Execute any command" by adding "Supports SQL queries".
- Verb forms in `-s`/`-es`/`-ies` are matched ("Deletes a file" was missed).
- Untrusted text printing also neutralizes bidi and zero-width characters.
- The stdio process handling is shared by `--live` and `--run` (output caps, deadlines, process-tree kill).

## v0.3.0

### Added
- **Tool poisoning detection** (`tool-poisoning`): instructions for the model hidden in tool descriptions, parameter descriptions and schema titles. Strong signals (override phrases, concealment from the user, smuggled Unicode tag characters) or two weak ones (hidden tags such as `<IMPORTANT>`/`<system>`, HTML comments addressed to the model, directives about another tool, sensitive file access such as `~/.ssh` or `mcp.json`, invisible characters) give CRITICAL; a single weak signal gives HIGH. Text is normalized first (HTML entities, invisible characters, NFKC, Cyrillic/Greek look-alikes, curly quotes, whitespace) and size-capped against ReDoS. Works with `--live`.
- `inspect` prints a **TOOL POISONING DETECTED** alert under the table.
- `examples/poisoned_tools.json` to try it.
- **PyPI publishing**: `pipx install mcp-guard-audit` (the PyPI name; the command stays `mcp-guard`, as `mcp-guard` is too close to an existing PyPI project). Releases are published by `.github/workflows/publish.yml` with Trusted Publishing (OIDC, no stored token), after the tests pass and the tag matches the package version.
- `py.typed` marker, richer package metadata.

## v0.2.0

### Added
- **`--live`**: starts stdio servers or contacts Streamable HTTP servers, performs the MCP handshake and audits the full paginated `tools/list`. The tool asks for confirmation before running anything (`--yes` for CI) and bounds each server with `--timeout`. A failure is reported as `live-discovery-failed`.
- **More config formats**: Zed (`context_servers`, flat and nested `command`), Windsurf (`serverUrl`), Continue YAML (`mcpServers` list, standalone block files). YAML input is supported.
- **`--rules`**: custom rules file (YAML/JSON) to add, redefine or disable categories and ignore reviewed servers/tools. See `examples/rules.yaml`.
- **`--format sarif`** for GitHub code scanning (security-severity, line numbers, fingerprints), plus `-o/--output`. See `examples/github-code-scanning.yml`.
- The table shows the detected config format.
- More mutating verbs in `write-operation`: add, save, store, update, replace.
- Secret references `${file:...}` (Windsurf) and `${{ secrets.X }}` (Continue) are recognized.

### Security
- `--live` confirmation shows the resolved program path, redacted arguments and env variable names, and warns about code-loading variables (`NODE_OPTIONS`, `LD_*`, `PYTHON*`...).
- `--live` refuses a bare command that resolves to the current directory (planted `npx.cmd`).
- HTTP redirects are never followed (no `Authorization` forwarding). Response size, total time, tool count and server requests are capped.
- The server process tree is killed after discovery (process group on POSIX, `taskkill /T` on Windows).
- Control characters in untrusted strings (names, args, server messages) are neutralized before printing.
- Error messages never include raw exception text, URLs with credentials or unbounded server strings.

### Changed
- `hardcoded-secret` also detects `--api-key X`, `API_KEY=X` (e.g. `docker -e`) and `scheme://user:pw@host` arguments.
- Servers from every known location in a file are merged (e.g. a settings file with both `servers` and `context_servers`).
- SARIF: one fingerprint per finding, and de-duplicated Continue names (`Name #2`) point to the right line.
- mcp-guard is now an installable package with an `mcp-guard` command (`pipx install git+https://github.com/ianewsfr-a11y/mcp-guard`). `python mcp_guard.py` is replaced by `mcp-guard` or `python -m mcp_guard`.
- `--json` is kept as a shortcut for `--format json`. JSON entries now include a `server` field (set for tools found by `--live`).
- New runtime dependency: `pyyaml`.

## v0.1.0

- First public release: `inspect` (Claude Desktop, Cursor and VS Code configs, tools lists) and `test-injection`.
