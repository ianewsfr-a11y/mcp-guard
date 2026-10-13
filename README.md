# mcp-guard

[![CI](https://github.com/ianewsfr-a11y/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/ianewsfr-a11y/mcp-guard/actions/workflows/ci.yml)

**Minimalist security audit CLI for MCP servers and AI agents.**

`mcp-guard` reads your Model Context Protocol (MCP) configuration or a server's tools list and tells you, in one table, which tools can execute commands, write data, touch a database, reach the network, or run with elevated privileges. It also ships a prompt-injection test kit to check how your agent reacts to hostile tool output.

By default it runs entirely offline and never executes the servers it audits. The opt-in `--live` mode starts them to read their real tools list.

```
$ mcp-guard inspect config_example.json
┌────────┬────────────────────────┬──────────┬──────────────────────────────────────────────┐
│ Type   │ Name                   │   Risk   │ Findings                                     │
├────────┼────────────────────────┼──────────┼──────────────────────────────────────────────┤
│ server │ ops-toolbox            │ CRITICAL │ privileged-access: sudo                      │
│        │                        │          │ hardcoded-secret: env                        │
│        │                        │          │ OPS_API_TOKEN=<redacted, 24 chars>           │
├────────┼────────────────────────┼──────────┼──────────────────────────────────────────────┤
│ tool   │ execute_bash_command   │ CRITICAL │ command-execution: bash, execute, shell      │
│        │                        │          │ privileged-access: root                      │
├────────┼────────────────────────┼──────────┼──────────────────────────────────────────────┤
│ tool   │ update_customer_record │   HIGH   │ write-operation: update                      │
│        │                        │          │ database-write: update                       │
│        │                        │          │ database: database, query, sql, table        │
├────────┼────────────────────────┼──────────┼──────────────────────────────────────────────┤
│ tool   │ fetch_url              │  MEDIUM  │ network: download, fetch, http, url          │
├────────┼────────────────────────┼──────────┼──────────────────────────────────────────────┤
│ server │ filesystem             │   LOW    │ no risky capability detected                 │
├────────┼────────────────────────┼──────────┼──────────────────────────────────────────────┤
│ tool   │ read_user_file         │   LOW    │ no risky capability detected                 │
└────────┴────────────────────────┴──────────┴──────────────────────────────────────────────┘
        format: mcpServers (Claude Desktop / Cursor / Windsurf / Continue) + tools list
6 item(s) audited   CRITICAL 2   HIGH 1   MEDIUM 1   LOW 2
```

## Installation

Requires Python 3.10+.

```bash
pipx install git+https://github.com/ianewsfr-a11y/mcp-guard
# or, in a virtualenv:
pip install git+https://github.com/ianewsfr-a11y/mcp-guard
```

This installs the `mcp-guard` command. `python -m mcp_guard` works too.

## Commands

### `inspect <config_file>`

Audits a config file. JSON, JSONC (comments, trailing commas), YAML and UTF-8 BOM are accepted, and the format is detected automatically:

| Client | File | Shape |
|---|---|---|
| Claude Desktop, Cursor | `claude_desktop_config.json`, `.cursor/mcp.json` | `{"mcpServers": {...}}` |
| Windsurf | `mcp_config.json` | `{"mcpServers": {...}}` with `serverUrl` for remote servers |
| VS Code | `.vscode/mcp.json`, `settings.json` | `{"servers": {...}}` or `{"mcp": {"servers": {...}}}` |
| Zed | `settings.json` | `{"context_servers": {...}}` |
| Continue | `config.yaml`, `.continue/mcpServers/*.yaml` | `mcpServers:` list of `- name: ...` |
| Any server | `tools/list` dump | `{"tools": [...]}`, a bare `[...]`, or `{"result": {"tools": [...]}}` |

```bash
mcp-guard inspect ~/.cursor/mcp.json
mcp-guard inspect config.yaml --format json              # machine-readable
mcp-guard inspect .vscode/mcp.json --fail-on high        # exit 1 in CI
mcp-guard inspect .vscode/mcp.json --format sarif -o mcp-guard.sarif
mcp-guard inspect mcp.json --rules team-rules.yaml       # custom rules
mcp-guard inspect mcp.json --live                        # audit the real tools
```

Exit codes: `0` audit done, `1` `--fail-on` threshold reached, `2` unreadable input. A single malformed server or tool does not abort the audit: it is reported as `malformed-entry` and the rest is analyzed.

**What it checks**

| Category | Risk | Signals |
|---|---|---|
| `command-execution` | CRITICAL | exec, shell, bash, eval, subprocess, spawn, script... |
| `privileged-access` | CRITICAL | root, sudo, admin, privileged, chmod... and Docker `--privileged`, `--cap-add`, `--pid=host`, `--network=host` |
| `write-operation` | HIGH | write, delete, remove, create, add, update, save, edit, move, rename, patch, push, commit... |
| `database-write` | HIGH | insert/update/delete/drop *next to* sql/db/table |
| `hardcoded-secret` | HIGH | literal values for `*_TOKEN`, `*_KEY`, `*_SECRET`, `*PASSWORD`, `Authorization` in `env` or `headers`; `--api-key=X`, `--api-key X` and `API_KEY=X` args; credentials in the server URL or in a `scheme://user:pw@host` arg. Values are never printed. References such as `${env:X}`, `${input:x}`, `${file:/path}`, `${{ secrets.X }}`, `$VAR` and `%VAR%` are ignored |
| `broad-filesystem-scope` | HIGH | a server arg that is exactly `/`, `~`, `C:\`, `/home`, `/Users`, `/etc`, `/root`, `$HOME` or `%USERPROFILE%` |
| `database` | MEDIUM | sql, query, database, postgres, redis... |
| `network` | MEDIUM | http, url, fetch, download, upload, webhook, email... |
| `insecure-transport` | MEDIUM | remote server URL over plain `http://` (localhost is fine) |
| `malformed-entry` | MEDIUM | an entry that could not be parsed: audit it by hand |
| `live-discovery-failed` | MEDIUM | `--live` could not start or reach the server |

Tool names (snake_case and camelCase), descriptions and input-schema property names are tokenized and matched as whole words, so `executive_summary` does not trigger `exec`. For servers, only the executable and package names are matched: flags and paths are skipped, and a shell launcher such as `cmd /c` or `bash -c` is judged on what it runs. An item's risk is its highest finding.

#### `--live`: audit the real tools

A config file only says how to *start* a server. With `--live`, mcp-guard starts each stdio server (or contacts each Streamable HTTP server), performs the MCP handshake, reads the full paginated `tools/list`, and audits every tool it exposes:

```
│ tool   │ memory > delete_entities     │   HIGH   │ write-operation: delete      │
│ tool   │ memory > search_nodes        │  MEDIUM  │ database: query              │
```

**This runs the commands written in your config**, with your user's permissions. mcp-guard lists them and asks for confirmation first. `--yes` skips the prompt, for CI. Safeguards:

- The prompt shows the resolved program path, the arguments with secrets redacted, and the names of the environment variables passed to the server. It warns about variables that make a launcher load other code (`NODE_OPTIONS`, `LD_PRELOAD`, `PYTHONPATH`...).
- A bare command (`npx`) must be found on `PATH`. mcp-guard refuses one that resolves to the current directory, which is where a cloned repository could plant a fake `npx.cmd`.
- HTTP redirects are never followed, so your `Authorization` header cannot be forwarded to another host.
- Output size, tool count, server-to-client requests and time are capped, and the whole process tree is killed afterwards.
- Disabled servers (`"disabled": true`) are skipped. `--timeout` (default 20 s) bounds each server. The legacy HTTP+SSE transport (protocol 2024-11-05) is not supported.

#### `--rules`: custom rules

A YAML or JSON file can add categories, redefine keyword rules, disable any category (built-in checks such as `hardcoded-secret` included), and ignore reviewed items. Keywords are single words, matched like tool-name tokens. Unknown or duplicate categories are rejected so a typo does not silently do nothing. See [`examples/rules.yaml`](examples/rules.yaml):

```yaml
extends: default          # or `none` to start from scratch
disable: [network]
rules:
  - category: payments
    risk: CRITICAL
    description: The tool can move money.
    keywords: [refund, payout, charge, transfer]
ignore:
  - read_user_file        # a tool name, a server name, or "server > tool"
```

#### `--format sarif`: GitHub code scanning

The SARIF 2.1.0 output carries GitHub's `security-severity`, a line number for each finding and stable fingerprints, so alerts show up in the repository's **Security** tab and on pull requests. A ready-to-copy workflow lives in [`examples/github-code-scanning.yml`](examples/github-code-scanning.yml).

### `test-injection <server_script>`

Prints 8 MCP-oriented prompt-injection payloads, covering instruction override, tool poisoning, cross-tool shadowing, fake system messages, URL exfiltration, hidden markup, consent bypass and encoded instructions. Each one says where to inject it and what a safe agent should do.

```bash
mcp-guard test-injection path/to/my_server.py
mcp-guard test-injection path/to/my_server.py --json > payloads.json
```

Every payload uses the canary `MCPGUARD-CANARY-7F3A` and the reserved `.invalid` domain. If the canary shows up in your agent's answer, or a tool gets called because of a payload, the agent is vulnerable. `mcp-guard` does not run the target script; you inject the payloads into your own test setup.

## Use case: audit before you install

You found a promising MCP server and want to add it to Claude Desktop. Before restarting the app:

1. Put its entry in a scratch `candidate.json` (`{"mcpServers": {"candidate": {...}}}`).
2. Run `mcp-guard inspect candidate.json --live` to start it once and audit the tools it really exposes.
3. A `CRITICAL` row such as `candidate > run_command` with `command-execution` tells you this server can run arbitrary commands on your machine. Decide whether you want that, sandbox it (container, restricted user), or skip it.
4. Run `inspect` on your own `claude_desktop_config.json` too: a `hardcoded-secret` finding means an API key sits in plain text in a file that often gets copied into gists and dotfile repos.

In CI, add `--fail-on critical` so a pull request that adds a shell-capable tool fails the build until someone reviews it.

## Limits

`mcp-guard` is a heuristic, keyword-based first pass. It reads declarations, not behavior: a tool named `get_weather` that secretly runs shell commands will look LOW, even in `--live` mode. Use it to triage and start the conversation, not as proof of safety.

## Development

```bash
git clone https://github.com/ianewsfr-a11y/mcp-guard.git
cd mcp-guard
pip install -e ".[dev]"
pytest --cov=mcp_guard --cov-report=term-missing
```

Contributions are welcome: new detection rules, config formats and payloads especially. Please open an issue first for larger changes. See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Going further: governance for teams

`mcp-guard` answers "what can this agent do?" on one machine. Teams running agents in production also need to answer "who approved it, what did it actually do, and can we prove it?". That is what **[Ergonia](https://ergonia.works)** is built for: governance and verifiable records for AI agent work at the organization level.

**[Discover Ergonia →](https://ergonia.works)**

## License

MIT, see [LICENSE](LICENSE).
