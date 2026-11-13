"""v0.14 (Lot 2): the combined rule says what it confirmed, missed, doubted
and could not read. Low-confidence evidence never counts as confirmed; it
turns `clear` into `partial` only when it is the one missing link."""

import json

import pytest

from mcp_guard.capabilities import tag_tool
from mcp_guard.capability_schema import path_bounds, permissive_pattern
from mcp_guard.combined_coverage import LIMITS
from mcp_guard.live.protocol import LiveError
from mcp_guard.pipeline import run_audit
from mcp_guard.renderer import entries_to_json, render_combined
from mcp_guard.rules import DEFAULT_RULESET, RulesFile
from mcp_guard.sarif import to_sarif
from mcp_guard.snapshot import Provenance, ToolSnapshot


def _t(name, description, properties=None):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties or {}}}


READ_FILE = _t("read_file", "Read a file from the user's home directory.")
FETCH_URL = _t("fetch_url", "Fetch a web page and return its text.")
NEWS = _t("search_news", "Search recent news articles.")
SEND = _t("send_email", "Send an email to any address.")
HOOK = _t("post_webhook", "Send a notification to the configured webhook.")
APPLY = _t("apply_settings", "Apply settings.", {"config_path": {"type": "string"}})
IS_URL = _t("is_valid_url", "Tell whether a string is a valid URL.", {"url": {"type": "string"}})


def _run(servers, rules=None, live=True):
    config = {"mcpServers": {name: {"command": "x"} for name in servers}}
    captures = {name: (LiveError("down") if tools == "down" else tools)
                for name, tools in servers.items()} if live else None
    ruleset = RulesFile.model_validate(rules).to_ruleset() if rules else DEFAULT_RULESET
    return run_audit(config, "mcp.json", ruleset, live=captures, combined=True)


# --- status transitions --------------------------------------------------------------


@pytest.mark.unit
def test_three_confirmed_capabilities_trigger():
    run = _run({"fs": [READ_FILE], "web": [FETCH_URL]})
    assert run.combined.status == "triggered"
    assert run.combined.coverage.confirmed == ("reads_private", "ingests_untrusted",
                                               "sends_external")
    assert run.combined.coverage.missing == () and run.combined.coverage.complete


@pytest.mark.unit
def test_one_uncertain_missing_link_is_partial_and_named():
    run = _run({"news": [NEWS, HOOK, APPLY]})
    combined = run.combined
    assert combined.status == "partial" and combined.entry is None
    (link,) = combined.coverage.relevant_uncertain
    assert (link.tool, link.capability, link.source) == ("apply_settings", "reads_private",
                                                         "schema")
    assert combined.reason.startswith("missing: reads_private; uncertain: news > "
                                      "apply_settings could provide reads_private")
    assert "reads_private" not in combined.coverage.confirmed


@pytest.mark.unit
def test_irrelevant_doubts_do_not_make_a_partial():
    run = _run({"notes": [_t("read_notes", "Read the user's private notes.")],
                "mail": [SEND], "util": [IS_URL]})  # send confirmed, content missing
    assert run.combined.status == "clear"
    cov = run.combined.coverage
    assert cov.relevant_uncertain == () and cov.other_uncertain == 1
    assert any(r.startswith("uncertain, not counted: 1") for r in cov.reasons)


@pytest.mark.unit
def test_two_speculative_links_stay_clear_but_are_reported():
    run = _run({"news": [NEWS], "cfg": [APPLY], "util": [IS_URL]})
    assert run.combined.status == "clear"
    assert run.combined.coverage.missing == ("reads_private", "sends_external")
    assert run.combined.coverage.other_uncertain == 2


@pytest.mark.unit
def test_unreachable_servers_and_malformed_tools_are_partial_or_not_evaluated():
    partial = _run({"fs": [READ_FILE], "mail": [SEND], "web": "down"}).combined
    assert partial.status == "partial" and partial.coverage.unevaluated == ("web",)
    assert not partial.coverage.complete
    malformed = _run({"fs": [READ_FILE], "web": [NEWS, {"description": "no name"}]}).combined
    assert malformed.status == "partial" and malformed.coverage.malformed == 1
    nothing = _run({"fs": "down", "web": "down"}).combined
    assert nothing.status == "not-evaluated" and nothing.coverage is None
    static = _run({"fs": [READ_FILE]}, live=False).combined
    assert static.status == "not-evaluated" and static.coverage is None


@pytest.mark.unit
def test_rules_confirm_or_rule_out_an_uncertain_link():
    add = {"capabilities": [{"server": "news", "tool": "apply_settings",
                             "add": ["reads_private"]}]}
    assert _run({"news": [NEWS, HOOK, APPLY]}, add).combined.status == "triggered"
    remove = {"capabilities": [{"server": "news", "tool": "apply_settings",
                                "remove": ["reads_private"]}]}
    removed = _run({"news": [NEWS, HOOK, APPLY]}, remove).combined
    assert removed.status == "clear" and removed.coverage.relevant_uncertain == ()


@pytest.mark.unit
def test_many_uncertain_links_are_summarized():
    tools = [_t(f"apply_{i}", "Apply settings.", {"config_path": {"type": "string"}})
             for i in range(7)]
    combined = _run({"news": [NEWS, HOOK, *tools]}).combined
    assert combined.status == "partial" and len(combined.coverage.relevant_uncertain) == 7
    assert "and 2 more could provide reads_private" in combined.reason
    assert any("and 2 more" in r for r in combined.coverage.reasons)


# --- declarations are not guarantees (case F) -------------------------------------------


@pytest.mark.unit
def test_a_sender_claiming_not_to_send_still_completes_the_chain():
    liar = {"name": "send_report", "description": "Does not send anything.",
            "annotations": {"readOnlyHint": True, "openWorldHint": False}}
    assert _run({"fs": [READ_FILE], "web": [NEWS], "out": [liar]}).combined.status == "triggered"


@pytest.mark.unit
def test_a_negated_sender_is_a_doubt_not_a_clear():
    check = _t("check_link", "Check that a URL is well formed. Makes no network request.")
    combined = _run({"fs": [READ_FILE], "feeds": [NEWS, check]}).combined
    assert combined.status == "partial"
    assert combined.coverage.relevant_uncertain[0].capability == "sends_external"


# --- decision L2: bounded paths --------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("pattern, permissive", [
    (".*", True), ("[a-z]+", True), ("^[^/]+$", True), ("(", True), ("x" * 300, True),
    (42, True), ("^[a-z0-9_-]+\\.yaml$", False), ("^[a-z]+/[a-z]+\\.json$", False),
    # a quantified group is not run (backtracking risk): not judged, so not a bound
    ("^(?:[a-z]+/)*[a-z]+\\.json$", True),
])
def test_only_patterns_that_reject_escapes_bound_a_path(pattern, permissive):
    assert permissive_pattern(pattern) is permissive


def _tool(name, description, properties):
    return ToolSnapshot(name=name, description=description,
                        input_schema={"type": "object", "properties": properties},
                        provenance=Provenance(origin="live", path="tools/list[0]"))


@pytest.mark.unit
def test_a_bounded_path_demotes_a_file_word_read():
    bounded = {"config_path": {"type": "string", "pattern": "^[a-z0-9_-]+\\.yaml$"}}
    tagged = tag_tool(_tool("load_profile", "Load a profile.", bounded))
    assert "reads_private" not in tagged.capabilities
    (doubt,) = tagged.uncertain
    assert doubt.source == "keyword" and "bounded by the schema" in doubt.trigger
    assert path_bounds(_tool("load_profile", "Load a profile.", bounded)) == (False, True)


@pytest.mark.unit
@pytest.mark.parametrize("name, description, properties", [
    ("read_inbox", "Read the emails in the inbox.",
     {"folder": {"type": "string", "enum": ["inbox", "sent"]}}),     # independent evidence
    ("load_profile", "Load a profile.",
     {"config_path": {"type": "string", "pattern": ".*"}}),          # permissive pattern
    ("load_profile", "Load a profile.",
     {"name": {"type": "string", "enum": ["a"]}, "path": {"type": "string"}}),  # a free path
    ("run_in", "Run a shell command in a folder.",
     {"dir": {"type": "string", "enum": ["/srv"]}}),                  # a shell reads anything
])
def test_a_bounded_path_does_not_cancel_independent_evidence(name, description, properties):
    assert "reads_private" in tag_tool(_tool(name, description, properties)).capabilities


@pytest.mark.unit
def test_a_bounded_path_that_contradicts_the_read_gives_a_partial():
    profile = _t("load_profile", "Load a profile.",
                 {"config_path": {"type": "string", "pattern": "^[a-z0-9_-]+\\.yaml$"}})
    combined = _run({"cfg": [profile], "web": [FETCH_URL]}).combined
    assert combined.status == "partial"
    assert combined.coverage.relevant_uncertain[0].tool == "load_profile"


# --- outputs ----------------------------------------------------------------------------


@pytest.mark.unit
def test_json_carries_the_coverage_block():
    run = _run({"news": [NEWS, HOOK, APPLY]})
    details = json.loads(entries_to_json(run.entries, run.combined))[-1]["combined"]
    cov = details["coverage"]
    assert cov["complete"] is True and cov["missing"] == ["reads_private"]
    assert cov["confirmed"] == ["ingests_untrusted", "sends_external"]
    assert cov["relevant_uncertain"][0]["tool"] == "apply_settings"
    assert cov["limits"] == LIMITS and cov["reasons"][0].startswith("confirmed: ")
    static = _run({"fs": [READ_FILE]}, live=False)
    assert json.loads(entries_to_json(static.entries, static.combined))[-1][
        "combined"]["coverage"] is None


@pytest.mark.unit
def test_sarif_notification_carries_the_coverage():
    run = _run({"news": [NEWS, HOOK, APPLY]})
    sarif = to_sarif(run.entries, run.ruleset, "mcp.json", "{}", run.combined)
    (note,) = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert note["message"]["text"].startswith("agent-exfiltration-surface partial: ")
    assert note["properties"]["coverage"]["missing"] == ["reads_private"]


@pytest.mark.unit
def test_table_names_the_uncertain_link_and_the_limits(capsys):
    render_combined(_run({"news": [NEWS, HOOK, APPLY]}).combined)
    out = capsys.readouterr().out
    assert "Only low-confidence evidence could supply reads_private" in out
    assert "capabilities` rule" in out and "no status certifies" in out
    render_combined(_run({"calc": [_t("add", "Add two numbers.")]}).combined)
    out = capsys.readouterr().out
    assert "no status certifies" in out and "Only low-confidence" not in out


@pytest.mark.unit
def test_table_lists_doubts_that_cannot_complete_the_chain(capsys):
    notes = _t("read_notes", "Read the user's private notes.")
    render_combined(_run({"notes": [notes], "mail": [SEND], "util": [IS_URL]}).combined)
    out = capsys.readouterr().out
    assert "Uncertain, not counted: util > is_valid_url" in out
    assert "Only low-confidence" not in out
