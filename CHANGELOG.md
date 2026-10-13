# Changelog

## v0.3.0

### Added
- **Tool poisoning detection** (`tool-poisoning`): instructions for the model hidden in tool descriptions, parameter descriptions and schema titles. Strong signals (override phrases, concealment from the user, smuggled Unicode tag characters) or two weak ones (hidden tags such as `<IMPORTANT>`/`<system>`, HTML comments addressed to the model, directives about another tool, sensitive file access such as `~/.ssh` or `mcp.json`, invisible characters) give CRITICAL; a single weak signal gives HIGH. Text is normalized first (HTML entities, invisible characters, NFKC, Cyrillic/Greek look-alikes, curly quotes, whitespace) and size-capped against ReDoS. Works with `--live`.
- `inspect` prints a **TOOL POISONING DETECTED** alert under the table.
- `examples/poisoned_tools.json` to try it.
- **PyPI publishing**: `pipx install mcp-guard`. Releases are published by `.github/workflows/publish.yml` with Trusted Publishing (OIDC, no stored token), after the tests pass and the tag matches the package version.
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
