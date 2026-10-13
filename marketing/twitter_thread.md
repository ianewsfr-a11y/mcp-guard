# Launch thread (X / Twitter)

Attach a screenshot of the `inspect` table to tweet 1 and a screenshot of the `test-injection` panel to tweet 4.

---

**1/5**
Your AI agent probably has more power than you think.

Every MCP server you add gives it new tools: shell, filesystem, database, network. Most of us add them by copy-pasting JSON from a README.

So I built mcp-guard: one command to see what your agent can actually do. 🧵

**2/5**
The problem: an MCP tool is just a name + a description + a schema. Your agent reads all of it and trusts it.

A tool called `execute_bash_command`, or a server launched with `sudo`, is one prompt injection away from running whatever a web page or a PDF tells it to.

**3/5**
`mcp-guard inspect config.json` reads Claude Desktop, Cursor and VS Code configs or any tools/list dump, and flags:

🔴 CRITICAL: shell exec, root/sudo
🟠 HIGH: disk writes, SQL writes, hardcoded API keys
🟡 MEDIUM: network, DB reads, plain http

`--fail-on high` puts it in your CI.

**4/5**
`mcp-guard test-injection` gives you 8 MCP-specific attack payloads: tool poisoning, cross-tool shadowing, fake [SYSTEM] messages, URL exfiltration, consent bypass...

Each carries a canary string. If it shows up in your agent's answer, you've found a hole before someone else does.

**5/5**
It's open source (MIT), one Python file, 3 deps, fully offline. It never runs the servers it audits.

⭐ github.com/ianewsfr-a11y/mcp-guard

For teams who need agent governance beyond one laptop: ergonia.works

Feedback and rule PRs welcome 🙏
