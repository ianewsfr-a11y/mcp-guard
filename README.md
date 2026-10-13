# mcp-guard

**Minimalist security audit CLI for MCP servers and AI agents.**

`mcp-guard` reads your Model Context Protocol (MCP) configuration or a server's tools list and tells you, in one table, which tools can execute commands, write to disk, touch a database, reach the network, or run with elevated privileges. It also ships a prompt-injection test kit to check how your agent reacts to hostile tool output.

It runs entirely offline, has three dependencies, and never executes the servers it audits.

```
$ python mcp_guard.py inspect config_example.json
┌────────┬────────────────────────┬──────────┬───────────────────────────────────────────────────┐
│ Type   │ Name                   │   Risk   │ Findings                                          │
├────────┼────────────────────────┼──────────┼───────────────────────────────────────────────────┤
│ server │ ops-toolbox            │ CRITICAL │ privileged-access: sudo                           │
│        │                        │          │ hardcoded-secret: env OPS_API_TOKEN=<redacted,    │
│        │                        │          │ 24 chars>                                         │
├────────┼────────────────────────┼──────────┼───────────────────────────────────────────────────┤
│ tool   │ execute_bash_command   │ CRITICAL │ command-execution: bash, execute, shell           │
│        │                        │          │ privileged-access: root                           │
├────────┼────────────────────────┼──────────┼───────────────────────────────────────────────────┤
│ tool   │ update_customer_record │   HIGH   │ database-write: update                            │
│        │                        │          │ database: database, query, sql, table             │
├────────┼────────────────────────┼──────────┼───────────────────────────────────────────────────┤
│ tool   │ fetch_url              │  MEDIUM  │ network: download, fetch, http, url               │
├────────┼────────────────────────┼──────────┼───────────────────────────────────────────────────┤
│ server │ filesystem             │   LOW    │ no risky capability detected                      │
├────────┼────────────────────────┼──────────┼───────────────────────────────────────────────────┤
│ tool   │ read_user_file         │   LOW    │ no risky capability detected                      │
└────────┴────────────────────────┴──────────┴───────────────────────────────────────────────────┘
6 item(s) audited   CRITICAL 2   HIGH 1   MEDIUM 1   LOW 2
```

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/ianewsfr-a11y/mcp-guard.git
cd mcp-guard
python -m venv venv
# Linux/macOS: source venv/bin/activate    Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Commands

### `inspect <config_file>`

Audits a JSON file (JSONC comments, trailing commas and UTF-8 BOM are accepted). The format is detected automatically:

| Input | Example |
|---|---|
| Claude Desktop / Cursor config | `{"mcpServers": {...}}` |
| VS Code config | `{"servers": {...}}` or `{"mcp": {"servers": {...}}}` |
| Tools list | `{"tools": [...]}` or a bare `[...]` |
| JSON-RPC `tools/list` response | `{"result": {"tools": [...]}}` |

```bash
python mcp_guard.py inspect config_example.json
python mcp_guard.py inspect config_example.json --json             # machine-readable
python mcp_guard.py inspect config_example.json --fail-on high     # exit 1 in CI
```

Exit codes: `0` audit done, `1` `--fail-on` threshold reached, `2` unreadable input. A single malformed server or tool does not abort the audit: it is reported as `malformed-entry` and the rest is analyzed.

**What it checks**

| Category | Risk | Signals |
|---|---|---|
| `command-execution` | CRITICAL | exec, shell, bash, eval, subprocess, spawn, script... |
| `privileged-access` | CRITICAL | root, sudo, admin, privileged, chmod... and Docker `--privileged`, `--cap-add`, `--pid=host`, `--network=host` |
| `write-operation` | HIGH | write, delete, remove, create, edit, move, rename, patch, push, commit... |
| `database-write` | HIGH | insert/update/delete/drop *next to* sql/db/table |
| `hardcoded-secret` | HIGH | literal values for `*_TOKEN`, `*_KEY`, `*_SECRET`, `*PASSWORD`, `Authorization` in `env` or `headers`, `--api-key=...` style args, credentials in the server URL. Values are never printed; `${input:...}`, `${env:...}`, `$VAR`, `%VAR%` references are ignored |
| `broad-filesystem-scope` | HIGH | a server arg that is exactly `/`, `~`, `C:\`, `/home`, `/Users`, `/etc`, `/root`, `$HOME` or `%USERPROFILE%` |
| `database` | MEDIUM | sql, query, database, postgres, redis... |
| `network` | MEDIUM | http, url, fetch, download, upload, webhook, email... |
| `insecure-transport` | MEDIUM | remote server URL over plain `http://` (localhost is fine) |
| `malformed-entry` | MEDIUM | an entry that could not be parsed: audit it by hand |

Tool names (snake_case and camelCase), descriptions and input-schema property names are tokenized and matched as whole words, so `executive_summary` does not trigger `exec`. For servers, only the executable and package names are matched: flags and paths are skipped, and a shell launcher such as `cmd /c` or `bash -c` is judged on what it runs. An item's risk is its highest finding.

### `test-injection <server_script>`

Prints 8 MCP-oriented prompt-injection payloads, covering instruction override, tool poisoning, cross-tool shadowing, fake system messages, URL exfiltration, hidden markup, consent bypass and encoded instructions. Each one says where to inject it and what a safe agent should do.

```bash
python mcp_guard.py test-injection path/to/my_server.py
python mcp_guard.py test-injection path/to/my_server.py --json > payloads.json
```

Every payload uses the canary `MCPGUARD-CANARY-7F3A` and the reserved `.invalid` domain. If the canary shows up in your agent's answer, or a tool gets called because of a payload, the agent is vulnerable. `mcp-guard` does not run the target script; you inject the payloads into your own test setup.

## Use case: audit before you install

You found a promising MCP server and want to add it to Claude Desktop. Before restarting the app:

1. Start the server once and save its `tools/list` response, or copy the `tools` from its README, into `candidate.json`.
2. Run `python mcp_guard.py inspect candidate.json`.
3. A `CRITICAL` row such as `run_command` with `command-execution` tells you this server can run arbitrary commands on your machine. Decide whether you want that, sandbox it (container, restricted user), or skip it.
4. Run `inspect` on your own `claude_desktop_config.json` too: a `hardcoded-secret` finding means an API key sits in plain text in a file that often gets copied into gists and dotfile repos.

In CI, add `--fail-on critical` so a pull request that adds a shell-capable tool fails the build until someone reviews it.

## Limits

`mcp-guard` is a heuristic, keyword-based first pass. It reads declarations, not behavior: a tool named `get_weather` that secretly runs shell commands will look LOW. Use it to triage and start the conversation, not as proof of safety.

## Development

```bash
pip install -r requirements-dev.txt
pytest --cov=mcp_guard --cov-report=term-missing
```

Contributions are welcome: new detection rules, config formats and payloads especially. Please open an issue first for larger changes.

## Going further: governance for teams

`mcp-guard` answers "what can this agent do?" on one machine. Teams running agents in production also need to answer "who approved it, what did it actually do, and can we prove it?". That is what **[Ergonia](https://ergonia.works)** is built for: governance and verifiable records for AI agent work at the organization level.

**[Discover Ergonia →](https://ergonia.works)**

## License

MIT, see [LICENSE](LICENSE).
