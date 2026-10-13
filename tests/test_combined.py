"""Experimental `agent-exfiltration-surface` (inspect --combined)."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard import DEFAULT_RULESET, collect, load_ruleset
from mcp_guard.analyzer import analyze
from mcp_guard.capabilities import CapabilityOverride, tag_tool
from mcp_guard.cli import cli
from mcp_guard.combined import RULE, combined_id, evaluate
from mcp_guard.pipeline import run_audit
from mcp_guard.renderer import entries_to_json
from mcp_guard.sarif import to_sarif
from mcp_guard.snapshot import Provenance, ToolSnapshot

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = json.loads((ROOT / "config_example.json").read_text(encoding="utf-8"))

READER = {"name": "read_file", "description": "Read a file from the user's disk.",
          "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}
FETCHER = {"name": "fetch_url", "description": "Fetch a web page from a URL."}
READ_MAIL = {"name": "read_inbox", "description": "Read the latest emails in the inbox."}
SENDER = {"name": "post_webhook", "description": "Send a message to a webhook."}
CALC = {"name": "add_numbers", "description": "Add two numbers."}

SERVERS = {"fs": {"command": "npx", "args": ["-y", "fs-server", "./data"]},
           "web": {"command": "npx", "args": ["-y", "web-server"]},
           "mail": {"command": "npx", "args": ["-y", "mail-server"]}}


def _run(live, servers=None, ruleset=DEFAULT_RULESET):
    data = {"mcpServers": servers or {name: SERVERS[name] for name in live}}
    snap = collect(data, "mcp.json", live)
    entries = analyze(snap, ruleset)
    return snap, entries, evaluate(snap, entries, ruleset)


def _tool(raw, server=None):
    return ToolSnapshot(name=raw["name"], description=raw.get("description", ""),
                        input_schema=raw.get("inputSchema", {}),
                        annotations=raw.get("annotations"),
                        provenance=Provenance(origin="live", path="tools/list[0]",
                                              server=server))


# --- capability tags --------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("raw, expected", [
    (READER, {"reads_private"}),
    (FETCHER, {"ingests_untrusted", "sends_external"}),  # dual role
    (READ_MAIL, {"reads_private", "ingests_untrusted"}),
    (SENDER, {"sends_external"}),
    (CALC, set()),
])
def test_keyword_tags(raw, expected):
    tagged = tag_tool(_tool(raw))
    assert set(tagged.capabilities) == expected
    assert all(t.source == "keyword" and t.trigger.startswith("keyword ") for t in tagged.tags)


@pytest.mark.unit
def test_annotation_adds_tags_but_cannot_remove_them():
    open_world = _tool({**CALC, "annotations": {"openWorldHint": True}})
    tags = {t.capability: t for t in tag_tool(open_world).tags}
    # many servers set openWorldHint on every tool: it is not an outbound channel
    assert set(tags) == {"ingests_untrusted"}
    assert tags["ingests_untrusted"].source == "annotation"
    closed = _tool({**FETCHER, "annotations": {"openWorldHint": False}})
    assert set(tag_tool(closed).capabilities) == {"ingests_untrusted", "sends_external"}


@pytest.mark.unit
def test_rule_overrides_have_top_priority_and_can_remove():
    tool = _tool({**FETCHER, "annotations": {"openWorldHint": True}}, server="web")
    overrides = (CapabilityOverride(server="web", add={"reads_private"},
                                    remove={"sends_external"}),)
    tags = {t.capability: t for t in tag_tool(tool, overrides).tags}
    assert set(tags) == {"reads_private", "ingests_untrusted"}
    assert tags["reads_private"].source == "rule"
    assert tags["reads_private"].trigger == "rules: add on web"
    assert tags["ingests_untrusted"].source == "annotation"  # annotation > keyword
    by_tool = (CapabilityOverride(tool="fetch_url", add={"reads_private"}),)
    assert "reads_private" in tag_tool(tool, by_tool).capabilities
    other = (CapabilityOverride(server="other", add={"reads_private"}),)
    assert "reads_private" not in tag_tool(tool, other).capabilities


@pytest.mark.unit
@pytest.mark.parametrize("bad, message", [
    ({"add": ["reads_private"]}, "needs `server`, `tool`"),
    ({"tool": "t"}, "needs `add` or `remove`"),
    ({"tool": "t", "add": ["sends_external"], "remove": ["sends_external"]}, "both add"),
    ({"tool": "t", "add": ["reads_everything"]}, "reads_private"),
])
def test_invalid_overrides_are_rejected(bad, message):
    with pytest.raises(ValueError, match=message):
        CapabilityOverride.model_validate(bad)


# --- the rule ---------------------------------------------------------------------


@pytest.mark.unit
def test_three_capabilities_trigger_one_medium_finding():
    _, _entries, result = _run({"fs": [READER], "web": [FETCHER], "mail": [SENDER]})
    assert result.status == "triggered"
    finding = result.entry.findings[0]
    assert (finding.category, finding.risk.name) == (RULE, "MEDIUM")
    assert result.servers == ("fs", "mail", "web")
    assert finding.id == combined_id(("fs", "mail", "web"))
    assert "reads_private: fs > read_file" in finding.evidence
    assert "ingests_untrusted: web > fetch_url" in finding.evidence
    # sends_external has 2 tools (fetch_url, post_webhook): the least populated is cut
    assert result.cut_point == "ingests_untrusted"
    assert "Cut point: ingests_untrusted (1 tool(s): web > fetch_url)" in finding.evidence


@pytest.mark.unit
def test_two_out_of_three_is_not_a_finding():
    _, _, result = _run({"fs": [READER], "mail": [SENDER]})
    assert (result.status, result.entry) == ("clear", None)
    assert result.reason == "missing: ingests_untrusted"


@pytest.mark.unit
def test_a_dual_role_tool_completes_the_trifecta():
    _, _, result = _run({"fs": [READER], "web": [FETCHER]})
    assert result.status == "triggered"
    assert result.cut_point == "sends_external"  # tie: the outbound channel goes first
    assert [t.name for t in result.surface["sends_external"]] == ["fetch_url"]


@pytest.mark.unit
def test_disabled_and_ignored_servers_are_out_of_scope():
    servers = {**SERVERS, "web": {**SERVERS["web"], "disabled": True}}
    _, _, result = _run({"fs": [READER], "mail": [SENDER]}, servers=servers)
    assert result.status == "clear"
    ignoring = load_ruleset_from({"ignore": ["web"]})
    _, _, ignored = _run({"fs": [READER], "web": [FETCHER]}, ruleset=ignoring)
    assert ignored.status == "clear"


@pytest.mark.unit
def test_static_mode_is_not_evaluated_rather_than_clear():
    snap = collect({"mcpServers": SERVERS}, "mcp.json")
    result = evaluate(snap, analyze(snap), DEFAULT_RULESET)
    assert (result.status, result.entry) == ("not-evaluated", None)
    assert result.reason == "no tool list: run with --live"
    assert result.unevaluated == ("fs", "web", "mail")


@pytest.mark.unit
def test_unreached_servers_are_reported():
    from mcp_guard.live import LiveError
    _, _, failed = _run({"fs": LiveError("down"), "web": LiveError("down")})
    assert (failed.status, failed.reason) == ("not-evaluated", "no server could be reached")
    _, _, partial = _run({"fs": [READER], "web": [FETCHER], "mail": LiveError("down")})
    assert partial.status == "triggered" and partial.unevaluated == ("mail",)
    assert "Not evaluated (no tool list): mail" in partial.entry.findings[0].evidence


@pytest.mark.unit
def test_broad_filesystem_scope_on_a_reader_raises_to_high_never_critical():
    servers = {**SERVERS, "fs": {"command": "npx", "args": ["-y", "fs-server", "/"]}}
    _, _, result = _run({"fs": [READER], "web": [FETCHER]}, servers=servers)
    assert result.entry.findings[0].risk.name == "HIGH"
    shell = {"name": "run_shell", "description": "Execute a shell command and read files."}
    _, _, worst = _run({"fs": [READER, shell], "web": [FETCHER]}, servers=servers)
    assert worst.entry.findings[0].risk.name == "HIGH"
    # broad scope on a server that only provides the outbound side: still MEDIUM
    servers = {**SERVERS, "web": {"command": "npx", "args": ["-y", "web-server", "~"]}}
    _, _, other = _run({"fs": [READER], "web": [FETCHER]}, servers=servers)
    assert other.entry.findings[0].risk.name == "MEDIUM"


@pytest.mark.unit
def test_fingerprint_is_stable_when_a_tool_joins_an_involved_server():
    _, _, before = _run({"fs": [READER], "web": [FETCHER]})
    more = {"name": "read_notes", "description": "Read the user's notes."}
    _, _, after = _run({"fs": [READER, more], "web": [FETCHER]})
    assert before.entry.findings[0].id == after.entry.findings[0].id
    assert before.entry.findings[0].evidence != after.entry.findings[0].evidence
    _, _, third = _run({"fs": [READER], "web": [FETCHER], "mail": [SENDER]})
    assert third.entry.findings[0].id != before.entry.findings[0].id  # new server involved


def load_ruleset_from(data, tmp=Path(__file__).parent / "_combined_rules.json"):
    tmp.write_text(json.dumps(data), encoding="utf-8")
    try:
        return load_ruleset(tmp)
    finally:
        tmp.unlink()


@pytest.mark.unit
def test_rules_file_overrides_disable_and_validation():
    removing = load_ruleset_from({"capabilities": [
        {"server": "web", "tool": "fetch_url", "remove": ["sends_external"]}]})
    _, _, result = _run({"fs": [READER], "web": [FETCHER]}, ruleset=removing)
    assert result.status == "clear"
    adding = load_ruleset_from({"capabilities": [{"tool": "add_numbers",
                                                  "add": ["sends_external"]}]})
    _, _, added = _run({"fs": [READER, CALC], "web": [{**FETCHER, "name": "get_page",
                                                       "description": "Get a web page."}]},
                       ruleset=adding)
    assert added.status == "triggered"
    sends = added.surface["sends_external"]
    assert [(t.name, t.tags[-1].source) for t in sends] == [("add_numbers", "rule")]
    disabled = load_ruleset_from({"disable": [RULE]})
    _, _, off = _run({"fs": [READER], "web": [FETCHER]}, ruleset=disabled)
    assert (off.status, off.entry) == ("disabled", None)
    with pytest.raises(Exception, match="reserved"):
        load_ruleset_from({"rules": [{"category": RULE, "risk": "LOW", "keywords": ["x"]}]})


# --- outputs ----------------------------------------------------------------------


def _audit(live, combined=True):
    data = {"mcpServers": {name: SERVERS[name] for name in live}}
    return run_audit(data, "mcp.json", DEFAULT_RULESET, live, combined=combined)


@pytest.mark.unit
def test_without_the_flag_nothing_changes():
    live = {"fs": [READER], "web": [FETCHER]}
    plain = _audit(live, combined=False)
    assert plain.combined is None and all(e.kind != "config" for e in plain.entries)
    flagged = _audit(live)
    assert [e for e in flagged.entries if e.kind != "config"] == list(plain.entries)


@pytest.mark.unit
def test_json_output_has_the_config_entry_and_its_details():
    run = _audit({"fs": [READER], "web": [FETCHER]})
    payload = json.loads(entries_to_json(run.entries, run.combined))
    config = [e for e in payload if e["kind"] == "config"]
    assert len(config) == 1 and config[0]["name"] == "mcp.json"
    details = config[0]["combined"]
    assert details["status"] == "triggered" and details["cut_point"] == "sends_external"
    assert details["surface"]["reads_private"] == [{
        "server": "fs", "tool": "read_file", "source": "keyword",
        "trigger": "keyword read + file"}]
    static = run_audit({"mcpServers": SERVERS}, "mcp.json", DEFAULT_RULESET, combined=True)
    payload = json.loads(entries_to_json(static.entries, static.combined))
    assert payload[-1]["combined"]["status"] == "not-evaluated"
    assert payload[-1]["findings"] == [] and payload[-1]["risk"] == "LOW"
    assert payload[-1]["name"] == "mcp.json"  # same name as a triggered config entry


CONFIG_TEXT = """{
  "mcpServers": {
    "fs": {"command": "npx"},
    "web": {"command": "npx"}
  }
}"""


@pytest.mark.unit
def test_sarif_points_at_the_servers_key_with_related_locations():
    run = _audit({"fs": [READER], "web": [FETCHER]})
    report = to_sarif(run.entries, run.ruleset, "mcp.json", CONFIG_TEXT, run.combined)
    result = next(r for r in report["runs"][0]["results"]
                  if r["ruleId"] == f"mcp-guard/{RULE}")
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    related = result["relatedLocations"]
    assert [(r["message"]["text"], r["physicalLocation"]["region"]["startLine"])
            for r in related] == [("server 'fs'", 3), ("server 'web'", 4)]
    assert result["partialFingerprints"]["mcpGuardFinding/v1"] == combined_id(("fs", "web"))
    rules = [r["id"] for r in report["runs"][0]["tool"]["driver"]["rules"]]
    assert f"mcp-guard/{RULE}" in rules


@pytest.mark.unit
def test_sarif_reports_not_evaluated_as_a_notification():
    run = run_audit({"mcpServers": SERVERS}, "mcp.json", DEFAULT_RULESET, combined=True)
    report = to_sarif(run.entries, run.ruleset, "mcp.json", CONFIG_TEXT, run.combined)
    notes = report["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert notes[0]["message"]["text"].startswith(f"{RULE} not-evaluated: ")
    plain = to_sarif(run.entries, run.ruleset, "mcp.json", CONFIG_TEXT)
    assert "invocations" not in plain["runs"][0]
    assert f"mcp-guard/{RULE}" not in json.dumps(plain)


@pytest.mark.integration
@pytest.mark.parametrize("fmt", ["table", "json", "sarif"])
def test_cli_combined_flag_is_opt_in(tmp_path, fmt):
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"tools": [READER, FETCHER]}), encoding="utf-8")
    plain = CliRunner().invoke(cli, ["inspect", str(config), "--format", fmt])
    flagged = CliRunner().invoke(cli, ["inspect", str(config), "--format", fmt, "--combined"])
    assert plain.exit_code == flagged.exit_code == 0
    assert RULE not in plain.output and RULE in flagged.output
    failing = CliRunner().invoke(cli, ["inspect", str(config), "--combined",
                                       "--fail-on", "medium"])
    assert failing.exit_code == 1


@pytest.mark.integration
def test_cli_combined_on_the_example_config():
    result = CliRunner().invoke(cli, ["inspect", str(ROOT / "config_example.json"),
                                      "--combined", "--format", "json"])
    config = next(e for e in json.loads(result.output) if e["kind"] == "config")
    assert config["combined"]["status"] == "triggered"
    assert config["combined"]["unevaluated"] == ["filesystem", "ops-toolbox"]  # config order


@pytest.mark.integration
def test_cli_table_shows_status_and_unevaluated_servers():
    static = CliRunner().invoke(cli, ["inspect", "--server", "npx -y a", "--combined"])
    text = " ".join(static.output.split())  # the terminal width wraps lines
    assert "NOT EVALUATED" in text and "run with --live" in text
    example = CliRunner().invoke(cli, ["inspect", str(ROOT / "config_example.json"),
                                       "--combined"])
    text = " ".join(example.output.replace("|", " ").replace("\u2502", " ").split())
    assert "Not evaluated (no tool list)" in text and "cut point" in text


@pytest.mark.unit
def test_a_reached_server_without_tools_is_evaluated():
    _, _, result = _run({"fs": []})
    assert result.status == "clear"
    assert result.reason == "missing: reads_private, ingests_untrusted, sends_external"


# --- review follow-ups --------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("raw, expected", [
    ({"name": "fetch_rows", "description": "Fetch rows from the table."}, {"reads_private"}),
    ({"name": "get_post", "description": "Get a blog post by id."}, {"ingests_untrusted"}),
    ({"name": "find_path", "description": "Find the shortest path in a graph."},
     {"reads_private"}),  # graph: a knowledge graph is private data; path alone is not
    ({"name": "run_command", "description": "Execute a shell command."},
     {"reads_private", "sends_external"}),
    ({"name": "execute_query", "description": "Execute a SQL query on the database."},
     {"reads_private"}),  # SQL context excuses "execute"
    ({"name": "create_issue", "description": "Create an issue in a GitHub repository."},
     {"sends_external"}),
    ({"name": "get_memory_usage", "description": "Get process memory usage."}, set()),
])
def test_vocabulary_regressions(raw, expected):
    assert set(tag_tool(_tool(raw), exceptions=DEFAULT_RULESET.exceptions).capabilities) \
        == expected


@pytest.mark.unit
def test_a_server_named_like_a_placeholder_does_not_merge_with_file_tools():
    snap = collect({"mcpServers": {"<tools list>": SERVERS["fs"]}, "tools": [FETCHER]},
                   "mcp.json", {"<tools list>": [READER]})
    result = evaluate(snap, analyze(snap), DEFAULT_RULESET)
    assert result.servers == ("<tools list>",) and result.file_tools
    assert result.entry.findings[0].id != combined_id(("<tools list>",))


@pytest.mark.unit
def test_an_ignored_server_name_does_not_hide_a_tool_with_that_name():
    ruleset = load_ruleset_from({"ignore": ["web"]})
    sneaky = {**FETCHER, "name": "web"}
    _, _, result = _run({"fs": [READER], "mail": [sneaky]}, servers=SERVERS, ruleset=ruleset)
    assert result.status == "triggered"  # web (the server) is ignored, mail > web is not
    by_tool = load_ruleset_from({"ignore": ["fetch_url"]})
    _, _, hidden = _run({"fs": [READER], "web": [FETCHER]}, ruleset=by_tool)
    assert hidden.status == "clear"  # a tool name in `ignore` still hides that tool


@pytest.mark.unit
def test_partial_when_a_capability_may_be_on_an_unreached_server():
    from mcp_guard.live import LiveError
    _, _, result = _run({"fs": [READER], "web": LiveError("down")})
    assert result.status == "partial" and result.entry is None
    assert "not evaluated (no tool list): web" in result.reason
    broken = {"description": "no name"}
    _, _, malformed = _run({"fs": [READER, broken]})
    assert (malformed.status, malformed.malformed) == ("partial", 1)
    assert "1 malformed tool(s) could not be tagged" in malformed.reason


@pytest.mark.unit
def test_all_servers_disabled_in_live_mode():
    servers = {"fs": {**SERVERS["fs"], "disabled": True}}
    snap = collect({"mcpServers": servers}, "mcp.json", {})
    result = evaluate(snap, analyze(snap), DEFAULT_RULESET)
    assert (result.status, result.reason) == ("not-evaluated", "no active server")


@pytest.mark.unit
def test_evidence_is_capped_but_surface_keeps_every_tool():
    readers = [{**READER, "name": f"read_file_{i}"} for i in range(25)]
    _, _, result = _run({"fs": readers, "web": [FETCHER]})
    evidence = result.entry.findings[0].evidence
    assert "and 15 more" in evidence and "read_file_24" not in evidence
    assert len(result.surface["reads_private"]) == 25


@pytest.mark.unit
def test_suppressed_tags_are_traced_in_json():
    ruleset = load_ruleset_from({"capabilities": [{"server": "web",
                                                   "remove": ["sends_external"]}]})
    data = {"mcpServers": {"fs": SERVERS["fs"], "web": SERVERS["web"]}}
    run = run_audit(data, "mcp.json", ruleset, {"fs": [READER], "web": [FETCHER]},
                    combined=True)
    details = json.loads(entries_to_json(run.entries, run.combined))[-1]["combined"]
    assert details["status"] == "clear"
    assert details["suppressed_by_rules"] == [
        {"server": "web", "tool": "fetch_url", "capabilities": ["sends_external"]}]


@pytest.mark.unit
def test_rules_file_with_capabilities_leaves_plain_output_unchanged():
    ruleset = load_ruleset_from({"capabilities": [{"tool": "read_file",
                                                   "remove": ["reads_private"]}]})
    data = {"mcpServers": {"fs": SERVERS["fs"], "web": SERVERS["web"]}}
    live = {"fs": [READER], "web": [FETCHER]}
    plain = run_audit(data, "mcp.json", DEFAULT_RULESET, live)
    with_caps = run_audit(data, "mcp.json", ruleset, live)
    assert entries_to_json(plain.entries) == entries_to_json(with_caps.entries)


@pytest.mark.unit
def test_combined_with_a_lock(tmp_path):
    from mcp_guard.lock import fingerprint, write_lock
    data = {"mcpServers": {"fs": SERVERS["fs"], "web": SERVERS["web"]}}
    live = {"fs": [READER], "web": [FETCHER]}
    lock = tmp_path / "mcp-guard.lock"
    write_lock(fingerprint(collect(data, "mcp.json", live)), lock)
    run = run_audit(data, "mcp.json", DEFAULT_RULESET, live, lock, combined=True)
    assert run.combined.status == "triggered"
    assert [e.kind for e in run.entries].count("config") == 1
