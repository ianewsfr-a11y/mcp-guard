"""v0.14 (Lot 1): capability evidence from schemas, negation, server context,
and confidence. A parameter is evidence, not proof; a negation demotes, it
never removes; low-confidence tags are reported, not counted."""

import json

import pytest

from mcp_guard.capabilities import CapabilityOverride, tag_tool, with_server_context
from mcp_guard.capability_schema import schema_tags
from mcp_guard.context import asserted_tokens, effective_tokens
from mcp_guard.pipeline import run_audit
from mcp_guard.renderer import entries_to_json, render_combined
from mcp_guard.rules import DEFAULT_RULESET
from mcp_guard.snapshot import Provenance, ToolSnapshot


def _tool(name, description, properties=None, server=None, annotations=None):
    return ToolSnapshot(name=name, description=description,
                        input_schema={"type": "object", "properties": properties or {}},
                        annotations=annotations,
                        provenance=Provenance(origin="live", path="tools/list[0]",
                                              server=server))


def _tags(tool):
    tagged = tag_tool(tool)
    return ({t.capability: t for t in tagged.tags},
            {t.capability: t for t in tagged.uncertain})


# --- decision L1-a: a path parameter is evidence, not proof -------------------------


@pytest.mark.unit
@pytest.mark.parametrize("description, spec, expected", [
    ("Read the configuration file at config_path and return its contents.",
     {"type": "string", "description": "Path to the file."}, "medium"),
    ("Load a profile.", {"type": "string", "pattern": "^[a-z0-9_-]+\\.yaml$"}, None),
    ("Load a profile.", {"type": "string", "enum": ["a.yaml", "b.yaml"]}, None),
    ("Select the active profile.",
     {"type": "string", "description": "Logical name; nothing is read from disk."}, "low"),
    ("Check that config_path points to a readable file. Returns true or false only.",
     {"type": "string"}, "low"),
    ("Apply settings.", {"type": "string", "description": "Optional configuration."}, "low"),
])
def test_free_path_parameters(description, spec, expected):
    found = [t for t in schema_tags(_tool("t", description, {"config_path": spec}))
             if t[0] == "reads_private"]
    assert [t[2] for t in found] == ([expected] if expected else [])


@pytest.mark.unit
def test_a_path_to_write_to_is_not_a_read():
    assert schema_tags(_tool("export_settings", "Write the current settings to a file.",
                             {"output_path": {"type": "string"}})) == []
    assert schema_tags(_tool("save", "Save the report.", {"path": {"type": "string"}})) == []


@pytest.mark.unit
def test_low_confidence_path_is_uncertain_not_counted():
    tags, uncertain = _tags(_tool("apply_settings", "Apply settings.",
                                  {"config_path": {"type": "string"}}))
    assert "reads_private" not in tags
    assert uncertain["reads_private"].source == "schema"
    assert "no evidence its content is returned" in uncertain["reads_private"].trigger


# --- URLs: validate, read, send ----------------------------------------------------------


@pytest.mark.unit
def test_url_parameters_follow_what_the_tool_does():
    fetch = _tags(_tool("fetch_page", "Download a web page and return its text.",
                        {"url": {"type": "string", "format": "uri"}}))[0]
    assert {"ingests_untrusted", "sends_external"} <= set(fetch)
    post = _tags(_tool("post_json", "POST a JSON payload.", {"target": {"format": "uri"}}))[0]
    assert post["sends_external"].source == "schema"
    check, doubt = _tags(_tool("is_valid_url", "Tell whether a string is a valid URL.",
                               {"url": {"type": "string"}}))
    assert not check and set(doubt) == {"sends_external"}
    assert schema_tags(_tool("pick", "Pick a mirror.",
                             {"url": {"type": "string", "enum": ["https://a.invalid"]}})) == []


@pytest.mark.unit
def test_the_word_url_alone_is_not_untrusted_content():
    tags, _ = _tags(_tool("notify_hook", "Send a webhook notification. Uses the webhook URL "
                                         "from an environment variable."))
    assert set(tags) == {"sends_external"}


# --- negation: a claim, not a guarantee ---------------------------------------------------


@pytest.mark.unit
def test_a_negated_request_is_demoted_not_removed():
    tags, uncertain = _tags(_tool("validate_url", "Check that a URL is well formed. Makes no "
                                                  "network request."))
    assert not tags
    assert uncertain["sends_external"].confidence == "low"
    assert "negated" in uncertain["sends_external"].trigger


@pytest.mark.unit
def test_a_negation_cannot_hide_an_asserted_send():
    tags, _ = _tags(_tool("sync", "Send the report to the URL. Makes no network request."))
    assert tags["sends_external"].confidence == "medium"
    tags, _ = _tags(_tool("upload_backup", "Upload the backup to the configured bucket. "
                                           "Does not send data anywhere else."))
    assert tags["sends_external"].confidence == "medium"


@pytest.mark.unit
def test_negation_stays_in_its_clause():
    text = "Never caches results. Sends the summary to the channel."
    assert "send" in asserted_tokens([text], {})
    negated = effective_tokens([text], {}) - asserted_tokens([text], {})
    assert negated == {"cach", "cache", "caches"} or "cache" in negated


@pytest.mark.unit
def test_a_negation_cannot_cancel_the_tool_name():
    assert "send" in asserted_tokens(["Does not send anything."], {}, None, "send_report")
    assert "send" not in asserted_tokens(["Does not send anything."], {}, None, "draft")
    tags, _ = _tags(_tool("send_report", "Does not send anything."))
    assert tags["sends_external"].confidence == "medium"


# --- paraphrases the keyword clauses now cover ------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("name, description, capability", [
    ("open_path", "Return the contents stored at a path on this machine.", "reads_private"),
    ("get_page", "Retrieve the page found at an address the assistant provides.",
     "ingests_untrusted"),
    ("get_page", "Retrieve the page found at an address the assistant provides.",
     "sends_external"),
    ("notify", "Deliver a message to a recipient.", "sends_external"),
    ("headlines", "List today's news.", "ingests_untrusted"),
])
def test_paraphrased_capabilities(name, description, capability):
    assert capability in tag_tool(_tool(name, description)).capabilities


@pytest.mark.unit
def test_a_notion_style_page_is_not_a_web_page():
    tags, _ = _tags(_tool("retrieve_page", "Retrieve a page of the workspace by its id."))
    assert "ingests_untrusted" not in tags and "sends_external" not in tags


# --- server context -----------------------------------------------------------------------


def _aggregator(server="news"):
    return [_tool("fetch_items", "Fetch articles from the configured feeds.", server=server),
            _tool("get_items", "Read the items of a run stage.", server=server),
            _tool("score_items", "Score the items of a stage.", server=server)]


@pytest.mark.unit
def test_reading_back_stored_third_party_content():
    tools = _aggregator()
    tagged = with_server_context([tag_tool(t) for t in tools], tools)
    by_name = {t.name: t for t in tagged}
    derived = by_name["get_items"].tag("ingests_untrusted")
    assert derived.source == "context" and "fetch_items" in derived.trigger
    assert "ingests_untrusted" not in by_name["score_items"].capabilities  # no read verb


@pytest.mark.unit
def test_server_context_needs_an_ingesting_tool_on_the_same_server():
    tools = [_aggregator("news")[0], _tool("get_items", "Read the items of a list.",
                                           server="todo")]
    tagged = with_server_context([tag_tool(t) for t in tools], tools)
    assert "ingests_untrusted" not in {t.name: t for t in tagged}["get_items"].capabilities


@pytest.mark.unit
def test_a_remove_rule_wins_over_server_context():
    tools = _aggregator()
    rule = (CapabilityOverride(server="news", tool="get_items", remove={"ingests_untrusted"}),)
    tagged = with_server_context([tag_tool(t, rule) for t in tools], tools, rule)
    assert "ingests_untrusted" not in {t.name: t for t in tagged}["get_items"].capabilities


@pytest.mark.unit
def test_rules_keep_top_confidence():
    tool = _tool("apply_settings", "Apply settings.", {"config_path": {"type": "string"}},
                 server="cfg")
    tagged = tag_tool(tool, (CapabilityOverride(server="cfg", add={"reads_private"}),))
    assert tagged.tag("reads_private").confidence == "high" and not tagged.uncertain


# --- combined rule: uncertain tags are shown, never counted -----------------------------


def _audit(servers):
    config = {"mcpServers": {name: {"command": "x"} for name in servers}}
    live = {name: [{"name": t[0], "description": t[1], "inputSchema": {
        "type": "object", "properties": t[2] if len(t) > 2 else {}}} for t in tools]
        for name, tools in servers.items()}
    return run_audit(config, "mcp.json", DEFAULT_RULESET, live=live, combined=True)


@pytest.mark.unit
def test_combined_lists_uncertain_tools_without_counting_them(capsys):
    run = _audit({"cfg": [("apply_settings", "Apply settings.", {"config_path": {}})],
                  "web": [("fetch_url", "Fetch a web page from a URL.")]})
    # v0.14: the low-confidence read is the only missing link, so the verdict is
    # partial (no finding), not clear; it is never counted as confirmed
    assert run.combined.status == "partial" and run.combined.entry is None
    assert "reads_private" in run.combined.reason
    assert "reads_private" not in run.combined.coverage.confirmed
    details = json.loads(entries_to_json(run.entries, run.combined))[-1]["combined"]
    assert details["uncertain"] == [{
        "server": "cfg", "tool": "apply_settings", "capability": "reads_private",
        "source": "schema",
        "trigger": "schema: free path parameter `config_path`; no evidence its content is "
                   "returned"}]
    render_combined(run.combined)
    out = capsys.readouterr().out
    # v0.14: the doubt is named once, as the link that would complete the chain
    assert "Only low-confidence evidence could supply reads_private" in out
    assert "Uncertain, not counted" not in out


@pytest.mark.unit
def test_combined_shows_uncertain_tools_when_triggered(capsys):
    run = _audit({"fs": [("read_file", "Read a file from the user's disk."),
                         ("is_valid_url", "Tell whether a string is a valid URL.",
                          {"url": {}})],
                  "web": [("fetch_url", "Fetch a web page from a URL.")]})
    assert run.combined.status == "triggered"
    render_combined(run.combined)
    assert "Uncertain, not counted" in capsys.readouterr().out
