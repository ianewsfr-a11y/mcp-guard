# GitHub Release: v0.1.0

**Tag:** `v0.1.0`
**Title:** `mcp-guard v0.1.0: first public release`

---

## mcp-guard v0.1.0

First public release of **mcp-guard**, a minimalist security audit CLI for Model Context Protocol (MCP) servers and AI agents.

### Highlights

- **`inspect <config_file>`**: audits MCP configurations and tool lists, then shows a colored risk table (LOW / MEDIUM / HIGH / CRITICAL).
  - Auto-detects Claude Desktop / Cursor (`mcpServers`), VS Code (`servers`, `mcp.servers`), `tools` lists, bare arrays and JSON-RPC `tools/list` responses.
  - Detects command execution, privileged access (incl. Docker `--privileged`), write operations, database reads/writes, network access, hardcoded secrets in `env`, `headers`, args and URLs (never printed), broad filesystem scope and plain-http transport.
  - Accepts JSONC (VS Code) and UTF-8 BOM; malformed entries are reported instead of aborting the audit.
  - Whole-word matching on snake_case/camelCase names, descriptions and input-schema properties.
  - `--json` output and `--fail-on <level>` for CI pipelines (exit `1` on threshold, `2` on unreadable input).
- **`test-injection <server_script>`**: 8 MCP-oriented prompt-injection payloads with canary-based success signals (`--json` export available). The target script is never executed.

### Install

```bash
git clone https://github.com/ianewsfr-a11y/mcp-guard.git
cd mcp-guard
pip install -r requirements.txt
python mcp_guard.py inspect config_example.json
```

### Known limitations

- Heuristic, keyword-based analysis: it reflects what tools *declare*, not their runtime behavior.
- No live connection to MCP servers yet (planned: fetch `tools/list` directly over stdio/HTTP).

### What's next

- Live `tools/list` discovery from a config
- More config formats (Windsurf, Zed, Continue)
- Custom rules file (`--rules rules.yaml`)
- SARIF output for GitHub code scanning

Feedback, issues and rule contributions are very welcome.

For organization-wide governance of AI agents, see [Ergonia](https://ergonia.works).

**Full changelog:** initial release
