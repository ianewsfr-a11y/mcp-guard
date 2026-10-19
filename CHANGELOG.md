# Changelog

## v0.10.0 (2026-10-19)

### Proxy journal: what an OpenTelemetry export needs (issue #29, step 1 of 2)
- **Each entry of `proxy --record` now says how a call ended**, read from the message the proxy already parses, without keeping the bodies: the tool name on a client's `tools/call` (`tool`) and the prompt name on `prompts/get` (`prompt`); on a response, the method of the request it answers (`answers`) and its `outcome` (`ok`, `tool_error` for a tool result with `isError: true`, `error` with its JSON-RPC `error_code`, `input_required` for a 2026-07-28 multi round-trip request, `unrecognized_result`, `malformed`); on `notifications/cancelled`, the id of the request it cancels (`cancels`). The names follow the OpenTelemetry semantic conventions for MCP. Error messages, arguments and results are still never written without `--record-bodies`.
- **A name is recorded only when it has the form of an MCP name** (letters, digits, `_`, `-`, `.`, at most 128): the client chooses it, so anything else, such as a token pasted as a tool name, is flagged as `tool_invalid` or `prompt_invalid` and not copied. A JSON-RPC batch is counted (`batch`), its members are not detailed. An integer id or error code too large to be one is not recorded.
- **W3C trace context:** a `traceparent` in `params._meta` (MCP 2026-07-28, SEP-414) is recorded when valid, and flagged as `traceparent_invalid` otherwise, never copied. `tracestate` and `baggage` can carry arbitrary application data and are not recorded.
- **The end line holds the server's exit code** (`server_exit`, `null` when the server did not start or the proxy was interrupted), to tell a server that stopped from a session that ended.

### `mcp-guard journal export`: the journal as OpenTelemetry traces (issue #29, step 2 of 2)
- **`journal export session.jsonl --otlp -o traces.json`** writes an OTLP/JSON trace export (`ExportTraceServiceRequest`) that a collector can load. Nothing is sent over the network. The export was checked against the official OTLP protobuf definitions.
- **One span per request**, opened by the request and closed by its response, by a `notifications/cancelled` from the side that sent it, or by the end of the run. It is named `{mcp.method.name} {tool or prompt}` and carries the attributes of the OpenTelemetry semantic conventions for MCP (development status): `mcp.method.name`, `gen_ai.tool.name`, `gen_ai.operation.name`, `jsonrpc.request.id`, `network.transport`, `rpc.response.status_code`, `error.type`. It also carries `mcp_guard.*` attributes: direction, outcome, run and trace origin. Spans are of kind INTERNAL: the proxy observes, it is neither client nor server.
- **Trace context:** a request that carried a valid `traceparent` joins that trace, as a child of the caller's span. Otherwise it is a local root, marked `mcp_guard.trace.origin = local`. Since MCP 2026-07-28 a connection is not a session, so local requests are not grouped under one trace; `mcp_guard.run` groups those of one proxy run.
- **Status:** a span is an error for:
  - `tool_error`;
  - a JSON-RPC error (`error.type` is its code);
  - `cancelled`;
  - `mcp_guard.transport_failure`: the server exited with a non-zero code while the request was pending;
  - `mcp_guard.no_response`: the run or the journal ended without an answer;
  - `unrecognized_result` and `malformed`.

  `input_required` is not an error.
- **Bodies are never exported,** even from a journal recorded with `--record-bodies`.
- **Every field is checked again on export,** since a journal can be edited:
  - a method or string id outside a plain charset is not exported (`_OTHER`);
  - an outcome the proxy never writes is `malformed`;
  - a time before 1970 skips the line;
  - a line longer than 1 MB, or nested too deeply to parse, is skipped and counted, and is not read whole.
- **Requests not exported are counted in the summary:** an id reused while a request was still open closes that request as `no_response`, and requests past 100,000 open or 200,000 spans are dropped and counted.
- **Ids and trace context:**
  - span ids and local trace ids derive from a random salt and the entry's place in the journal, never from the message, so the export cannot be used to confirm a guess of a message's content;
  - `--id-salt TEXT` makes an export repeatable;
  - `--local-traces` ignores incoming traceparents.
- **Output file:** it is written through a temporary file, readable by its owner only, and replaces a symbolic link instead of following it. It cannot be the journal itself.
- **Several runs in one file:** journals of several runs appended to one file are told apart by their end lines.

## v0.9.1 (2026-10-15)

### Fixed
- **A text ending with a backslash is printed as written** in the terminal reports of `inspect`, `scan` and the other commands. Rich's markup escaping doubled a final backslash, so a Windows drive given to a server (`C:\`) read `C:\\` in `broad-filesystem-scope`. Untrusted text now goes through `mcp_guard.markup.escape`, which keeps Rich's protection against markup injection.

## v0.9.0 (2026-10-15)

### `mcp-guard scan`: everything configured on the machine, in one command
- **Without arguments, `scan` finds the MCP configs of the clients installed on the machine**, audits each one with the same analysis as `inspect`, and prints the report by client, then by server. Clients covered (user files, and project files in the current directory):
  - **Claude Desktop**: `claude_desktop_config.json` (`%APPDATA%\Claude\`, `~/Library/Application Support/Claude/`);
  - **Claude Code**: `~/.claude.json` (user servers and each project's local servers, nothing else from that file) and `./.mcp.json`;
  - **Cursor**: `~/.cursor/mcp.json` and `./.cursor/mcp.json`;
  - **VS Code**: `~/.copilot/mcp-config.json` (or `$COPILOT_HOME`), the profile `Code/User/mcp.json`, and `./.vscode/mcp.json`;
  - **Windsurf (Devin Desktop)**: `~/.config/devin/mcp_config.json` (`%APPDATA%\devin\` on Windows) and the former `~/.codeium/windsurf/mcp_config.json`;
  - **Zed**: `settings.json` (`context_servers`);
  - **Continue**: `~/.continue/config.yaml`;
  - **Cline**: `~/.cline/data/settings/cline_mcp_settings.json` and its former VS Code extension storage;
  - **Roo Code**: `mcp_settings.json` in its VS Code extension storage.
- **Each path was checked against the client's official documentation or source** (2026-10-15). The ones they do not confirm are still searched and marked "not verified" in the code, the README and the report: Claude Desktop on Linux, `~/.claude.json` on Windows, the VS Code profile `mcp.json`, the former Windsurf and Cline paths, and Roo Code's folder.
- **Static only:** files are read, no server is started or contacted, no network request is made. A config larger than 10 MB, unreadable or not valid JSON/YAML is reported as "not read", with a warning, and the scan goes on. In the current directory, a config that is a symbolic link is not followed (a cloned repository could point it at any file of the user).
- **A server configured in several places is audited once**: two entries are the same server when their command, arguments, environment, headers, URL and `disabled` state are equal. The report lists every place it appears.
- **Exit code:** 0 by default, as with `inspect` (`--fail-on none`). `--fail-on high` exits with 1 when a server reaches HIGH or above, for CI.

### `--sarif` and `--json`
- **`scan --sarif`** writes a SARIF 2.1.0 log: the rules, one result per finding (level mapped from the severity), located in the config where the server was first found, the other places as `relatedLocations`. It is validated in the tests against the official OASIS SARIF 2.1.0 schema. **`scan --json`** lists the configs read (client, scope, status, servers), each distinct server with its findings and every place it was found, and a summary. `-o FILE` writes either report to a file. Both hold absolute paths (SARIF needs them); the terminal report shows `~`.

### `mcp-guard-audit` command
- **The CLI is also installed as `mcp-guard-audit`**, the PyPI package name, so `uvx mcp-guard-audit scan` runs without installing anything. `mcp-guard` is unchanged.

### Fixed: quadratic time on hostile JSONC files and in SARIF line lookup
- **Reading a hostile JSONC file no longer takes quadratic time.** This also affected `inspect`: a file full of unclosed `/*` comments or unclosed strings kept the comment stripper busy for minutes within a few MB. An unclosed comment or string now runs to the end of the text, matched once. Valid JSON and JSONC read as before.
- **SARIF line lookup is linear** on files with many blank lines (the YAML patterns no longer let `\s` span newlines), in `inspect --format sarif` and `scan --sarif`.

### URLs redacted in finding evidence
- **A URL in any finding's evidence shows only its scheme and host** (and port): the path, the query and the fragment are replaced by `[…]`, and userinfo is dropped. This applies to every finding, whoever builds it: `insecure-transport`, poisoning evidence that quotes a description, live errors, lock and proxy changes. A token carried in a remote MCP URL (`https://host/mcp/<token>`, `?session=<token>`) no longer reaches the table, the JSON, the SARIF report or the proxy's stderr. A poisoning payload hidden in a URL path or query is still detected; the evidence names the field and the host.

### Breaking
- **Finding ids changed, for every finding except poisoning and `--combined`.** An id (also the SARIF `partialFingerprints` value and the JSON `id`) is now computed from the category, the item (server, tool) and the field the finding is about (`env:API_KEY`, `args[2]`, `url`, `description`, `annotations.readOnlyHint`...), no longer from the evidence text, so a finding keeps its id when its evidence is reworded or redacted. GitHub code scanning will close the existing mcp-guard alerts once and open them again under the new fingerprints; JSON consumers that stored ids must re-baseline.
- **The proxy deduplicates lock and analysis findings by (category, item, field)**, not by the text of the line. A second, different change of the same field since the lock is no longer written again: the session comparison reports it. Session findings are still all written, with `(occurrence n)`.

### Tests
- Client paths per OS with a fake home and `APPDATA`/`XDG_CONFIG_HOME`, dedup across configs, Claude Code sections, unreadable and oversized configs, exit codes, SARIF validated against the official schema (vendored in `tests/fixtures`); `scan` runs with process creation and sockets disabled.
- A URL with a token in its path, query and fragment is absent from every output of `inspect` and `scan`; ids stay the same when only the evidence changes.

## v0.8.1 (2026-10-14)

### Breaking
- **New category `identity-changed` (MEDIUM)** for a changed server name, version or capabilities, in `inspect --lock` and in `proxy`. Until now it was `server-changed` MEDIUM, a category that is also HIGH for a changed command, arguments or URL, so `--fail-on` and SARIF consumers could not tell them apart. `server-changed` no longer reports identity changes: update the filters, SARIF queries and `--rules` entries that matched them through `server-changed`. ([#21](https://github.com/ianewsfr-a11y/mcp-guard/issues/21), reported by Jakub Hecht, @Duncopunc, in a thread on X.)

### Changed
- **An identity change re-arms the proxy session** (#21). The next complete `tools/list` is compared in full, with the lock and with the last list seen before the change, and every finding is written again with "after a server identity change". Poisoning and contradiction findings are written again once too, then deduplicated as before. This is the list that carries the change in its `_meta`, if it does. If the change came through `server/discover` or `initialize`, it is the next list.
- **Session findings are always written** (#22). Before, the proxy wrote each identical line only once, so in a session that flipped `readOnlyHint` true -> false -> true -> false, the third flip was hidden. From the second identical finding on, the line ends with `(occurrence n)`. Findings from the comparison with the lock, and poisoning or contradiction findings, are still written once: they are recomputed from the same reference on every list.
- **Changed arguments are reported with a multi-server lock** (#23). When no lock entry matches the command exactly and exactly one entry runs the same program, the proxy uses that entry, says so on stderr, and reports `command-pin-changed` HIGH ("arguments changed"). Before, it fell back to session-only mode with a note. Several entries running the same program are still ambiguous: the proxy asks for `--server-name`.
- **Proxy findings say when a tool now contradicts its own description**, as `inspect --lock` already did: "the tool now contradicts its own description (annotation-contradiction)".

### Tests
- Every security hint flipped in both directions, in the lock diff and in the proxy: always HIGH. The direction is in the evidence, not in the severity.

## v0.8.0 (2026-10-13)

### Breaking
- **A lock written by v0.8 cannot be read by v0.7.** Each server entry gains two fields: `pin` (command pinning, written by every `lock`) and `identity` (server name, version, protocol and a hash of its capabilities, written by `lock --live`). v0.7 validates locks strictly and rejects unknown fields. Upgrade every machine and CI job that reads the lock before you rewrite it with v0.8. A v0.7 lock is still read by v0.8.
- **The server's stderr is prefixed.** Through `proxy`, each line the server writes on stderr starts with `server: `, so it cannot pass for an `mcp-guard:` line. A client that parses the server's raw stderr will see the prefix.

### Upgrading from v0.7
- `lock` still writes format 2. Run `mcp-guard lock CONFIG --live --update` to add the pins and identities to an existing lock without approving anything else. It keeps the salt, and it refuses if a tool changed.

### Added
- **`mcp-guard proxy [--lock PATH] [--record PATH] [--record-bodies] [--server-name NAME] -- <cmd> <args...>`**: runs a stdio MCP server behind mcp-guard, between the client and the server.
  - **Transport:** every byte is forwarded unchanged and never re-serialized. Partial lines and messages of several MB are handled. Line endings are not translated (stdin and stdout are binary on Windows). Pure Python, no new dependency.
  - **Inspection on a copy, in its own thread:** `tools/list` requests (by id, pages by cursor) and their answers, `notifications/tools/list_changed`, `initialize`, `server/discover`, and the `_meta` serverInfo of any result.
    - Each complete tool list is compared with the lock and with the previous list of the session: description, schema, and each security hint flipped, as in `inspect --lock`.
    - Each list is also checked for poisoning and annotation contradictions.
  - **Reports:** on stderr, prefixed `mcp-guard:`, each line once. The server's stderr is relayed with each line prefixed `server: ` (also after a bare carriage return).
  - **Non-standard answers:** a `tools/list` answer without a `tools` array is noted and not compared, rather than read as a list of zero tools.
  - **Process:** SIGINT and SIGTERM are forwarded, the end of stdin is forwarded, and the proxy exits with the server's exit code (127 if the server cannot start).
  - **Hostile servers:**
    - Only a message without `method` that carries a `result` or an `error` counts as an answer, so a server request that reuses the id of a pending `tools/list` cannot hide that list.
    - Inspection is bounded: 1,000 lines or 64 MB waiting, 1,000 pending requests, 2,000 tools per list, 16 MB per line. Beyond these limits, messages are still forwarded but not inspected, and the proxy says so as soon as it happens.
    - A list nested too deeply to be fingerprinted is reported HIGH.
    - A lock nested too deeply to be read gives session-only mode.
  - **Fail-open, always.** A missing or unreadable lock, a journal that cannot be written, a message that is not JSON, or an internal error: the message is forwarded, the problem is reported on stderr, and the proxy goes on. There is no blocking mode. **The proxy prevents nothing; it makes changes visible.**
  - **Matching the lock:**
    - The lock entry is found from the pinned command.
    - If two entries run the same program with the same arguments, the proxy does not guess: it asks for `--server-name`.
    - If no entry matches, it says so with the command it saw and runs in session-only mode: comparisons within the session, and `readOnlyHint` flips after `list_changed`. A missing lock gives the same mode.
- **`--record PATH`**: a JSON-lines journal, written by a dedicated thread through a queue of 1,000 entries.
  - **When the queue is full:** entries are dropped and counted, never waited for. The count goes in a last `{"event": "end", "dropped": n}` line.
  - **Default entry:** time, direction, method, id (both capped at 128 characters), size and SHA-256.
  - **Format:** written as ASCII JSON, readable by its owner only (POSIX).
  - **`--record-bodies`:** adds the full message, with a warning that it can hold secrets.
- **Command pinning** (`pin` in the lock, written by `lock` for each stdio server). It holds:
  - the resolved executable path, with the home directory stored as `~`;
  - the arguments, in a strict form: no secret, only the scheme and host of a URL, no token-like word, `~` for the home directory. They are compared through a salted HMAC of their exact value (`args_hmac`), so a change is caught without the committed lock holding the value;
  - the name of the command as written in the config (`npx`, `python`), so that a symlink resolving differently on each machine does not change the program;
  - the SHA-256 of the executable and of the script it runs (`node server.js`), read without blocking and only from regular files;
  - the date.

  The proxy recomputes it in the background, after the server has started. A different hash, different arguments or another program is `command-pin-changed` HIGH. The same program and hashes at another path (`npx` lives somewhere else on every machine) is only a note. `lock --update` replaces the pin. A hash recorded in the lock that cannot be computed on this machine is said in a note, not skipped silently.
- **`secret-in-args`** (MEDIUM, in every audit): a launch argument that looks like a credential but that `hardcoded-secret` cannot name, such as `Authorization: Bearer x`, `password=` in a connection string, or a long random token. Pinned digests (`sha256:...`) are not reported. `lock` also warns about it. The pin compares arguments through an HMAC keyed by the lock's `salt`, and that salt sits in the lock itself. The HMAC therefore stops precomputed tables, but anyone who reads the lock can test guesses, so a guessable secret can be recovered from it. Pass secrets through env variables, whose values the lock never holds.
- **Server identity**: `serverInfo` and capabilities are recorded by `lock --live` and compared by `inspect --lock` and by the proxy. A change is `server-changed` MEDIUM: an upgrade is legitimate, but a rug pull would happen at exactly that moment. The negotiated protocol version is recorded but not compared, because it depends on the client.

### MCP revision 2026-07-28
Source: the specification changelog for that revision (major changes, point 3), relayed by the project owner. We could not check it from here, so the code documents these assumptions where it relies on them:
- **No `initialize` handshake.** `server/discover` announces the protocol versions, the capabilities and the server identity. The proxy does not wait for an `initialize`, and reads the identity from `server/discover`, from `initialize` (older revisions), or from `io.modelcontextprotocol/serverInfo` in the `_meta` of any result.
- **`server/discover` carries no tools.** If an answer contains a `tools` array anyway, the proxy logs it as a non-standard shape and does not treat it as a `tools/list` page.
- **`notifications/tools/list_changed`** is an ordinary line on stdio. With or without `io.modelcontextprotocol/subscriptionId`, the proxy notes it, and the subscription id when present.
- **`resultType`:** both forms are accepted and nothing is rewritten. An absent `resultType` means "complete".
- **Locks:** `ttlMs` and `cacheScope` are left out of the tool hash, so a cache hint does not look like a rug pull.

## v0.7.0

### Upgrading from v0.6
- **The terminal UI is now an extra.** After upgrading, `mcp-guard ui` asks for it. Reinstall with `pipx install --force "mcp-guard-audit[ui]"`, or `pip install --upgrade "mcp-guard-audit[ui]"`. Every other command works without it.
- **Lock file format 2, new severities.** v0.4 to v0.6 locks are still read and compared. Migrate one with `mcp-guard lock CONFIG --update` (add `--live` for a live lock): it keeps the salt, and refuses if anything changed since the lock was written. Severities:
  - description, annotation or input schema change HIGH;
  - other metadata MEDIUM;
  - tool added MEDIUM;
  - tool removed LOW.
- **Poisoning is checked on every surface** (tools, resources, prompts, server instructions) on a new scale: an injection marker alone HIGH, a URL or path alone MEDIUM, no CRITICAL. Replace `--fail-on critical` with `--fail-on high` in CI.
- **Snapshot digests of multi-server configs change**: servers are now sorted by name in the canonical form. Re-save the snapshots you keep as references.

### Added
- **Hidden-instruction detection on every text surface** of a snapshot, one finding per field:
  - `tool-poisoning`: name, title, description, input and output schema docs, string annotations;
  - `resource-poisoning`: resource name, title, description, URI, MIME type;
  - `prompt-poisoning`: prompt name, title, description, argument descriptions;
  - `server-instruction-poisoning`: the server's `instructions`, now captured with `--live`.

  Each finding has a stable id: a hash of rule, server, item and field path, so the id survives the attacker rewording the text. Evidence shows what matched after normalization and how the text is written (escaped).
- **New signals:**
  - secret or hidden instruction, approval bypass;
  - long base64 block, variation selectors, invisible characters written as HTML entities;
  - "before calling <another tool of the snapshot>", "always pass the full conversation";
  - any URL or absolute/home path in a description (but not in a resource URI);
  - wider override and concealment wording ("ignore previous rules", "skip informing the user").
- **Coverage:**
  - schema `enum`, `const`, `default` and `examples` strings and property names are scanned;
  - long texts are scanned head and tail, and the cut is reported HIGH, as are fields left out;
  - three or more flagged fields in one item make each of their findings HIGH;
  - server `instructions` are capped at 20,000 characters, stored with URL credentials removed, and compared by `snapshot diff`.
- **`mcp-guard snapshot diff OLD NEW`**: compares two snapshots and shows how the attack surface moved.
  - **What it reports:** servers and tools added, removed or changed.
  - **Tool changes:** for a tool kept in both, the description (old and new text), input schema, annotations and metadata, path by path (`$.properties.note`), plus its risk and finding categories before and after.
  - **Rug pulls:** a tool that keeps its name but changes what it tells the model is flagged as a possible rug pull.
  - **Server changes:** spec in redacted form, live status, resources and prompts.
  - **`--combined`:** also compares the `agent-exfiltration-surface` result (status, risk, id, cut point, tools per capability).
  - **Outputs:** a Rich table by default. `--format json` gives a structured export (`mcp-guard-diff/1`) for CI or other tools.
  - **Options:** `--exit-code` exits with 1 when the surface changed, and `--rules` rates both sides.
- **`mcp-guard snapshot save`**: writes a snapshot file (static, or `--live`), with secrets redacted. Until now snapshots were only reachable from the Python API, so `diff` had nothing to compare from the command line.
- **`inspect --combined` (experimental)**: config-level rule `agent-exfiltration-surface`.
  - **Trigger:** together, the active servers let an agent read private data, ingest untrusted content and send data out.
  - **Finding:** one per config. MEDIUM, or HIGH with `broad-filesystem-scope` on a server that reads private data. It lists the tools behind each capability and the cut point.
  - **Id:** stable per set of servers involved.
  - **Statuses:** without a tool list the rule reports "not evaluated". When servers were not reached or tools could not be parsed, it reports "partial" instead of "no finding". Neither changes the exit code, and both are SARIF notifications.
  - **Outputs:** table row of type `config`, JSON details with each tag's provenance, and in SARIF a location on the servers key with related locations.
- **Capability tags** (`reads_private`, `ingests_untrusted`, `sends_external`), separate from risk categories.
  - **Sources:** keywords (shell tools count as reader and outbound channel), the MCP `openWorldHint` annotation (adds `ingests_untrusted` only, never removes a tag), and a new `capabilities` section in `--rules` to add or remove tags per tool or server (`remove` wins, traced in JSON).
- Without `--combined`, this rule changes no output: table, JSON and SARIF stay as without it.
- **`annotation-contradiction`** (HIGH, active in every audit): `readOnlyHint: true` on a tool that writes or runs commands, or `destructiveHint: false` on a tool that deletes, overwrites or runs commands.
  - Write and delete words count in the name, title or first word of the description. Command words count anywhere.
  - No finding on the official memory, filesystem, fetch, git and time servers (38 tools).
  - With `--lock`, the evidence of an annotation change also says when the tool now contradicts itself.
  - New SARIF rule `mcp-guard/annotation-contradiction`.
- **Lock diff, security hints:** each change to `readOnlyHint`, `destructiveHint`, `idempotentHint` or `openWorldHint` is reported separately and explicitly: flipped either way, removed, or added.
- **`lock --update`**: migrates an existing lock to the current format, keeping its salt. It refuses, without touching the file, if anything changed since the lock was written.
- **Lock diff, hidden edits:** a description that changes only by invisible characters, look-alike letters or formatting is named as such, and the current text is shown escaped (code points and Unicode names).

### Changed
- **Textual is now optional.** `mcp-guard ui` needs the `ui` extra: `pip install "mcp-guard-audit[ui]"`, or with pipx `pipx install --force "mcp-guard-audit[ui]"`. The base install no longer pulls Textual, which keeps CI installs light. All other commands work without it. Without it, `mcp-guard ui` exits with code 1 before doing any work, and says how to add the extra, naming the installed distribution. **Upgrading an existing install removes the UI until you add the extra**: run `pipx install --force "mcp-guard-audit[ui]"`, or `pip install --upgrade "mcp-guard-audit[ui]"`.
- **Poisoning severity scale:**
  - HIGH: an injection marker on its own (override, concealment, hidden tag, approval bypass), invisible text, or two different signals;
  - MEDIUM: a URL, a path or a cross-reference on its own;
  - no CRITICAL anymore: these were CRITICAL before. A CI gate with `--fail-on critical` no longer fails on poisoning, so use `--fail-on high`.
- Reports without any poisoning finding are byte-identical to before. The three new categories only appear in SARIF when they report something.
- **Lock file format 2.** Per tool, it stores the security hint values, a hash of the annotations and a hash of the normalized description. Format 1 locks are still read and compared as before.
- **Lock diff severities:** description, annotation or input schema change HIGH; other metadata (title, output schema) MEDIUM, was HIGH; tool added MEDIUM; tool removed LOW.
- **Key order never matters:** snapshot digests sort servers by name, and lock files are written with servers and tools in a fixed order.
  - Reordering servers or object keys in a config changes neither.
  - The digest of a multi-server snapshot can differ from the one v0.6.0 computed for the same setup.

## v0.6.0

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
