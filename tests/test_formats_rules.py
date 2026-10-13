"""v0.2: more config formats and custom rules files."""

import json

import pytest

from mcp_guard import ConfigFormatError, Risk, audit, discover, load_config, load_ruleset


def _names(entries):
    return {e.name: e for e in entries}


# --- Formats ---------------------------------------------------------------


@pytest.mark.unit
def test_zed_context_servers_flat_and_nested():
    data = {"context_servers": {
        "flat": {"command": "sudo", "args": ["node", "a.js"]},
        "nested": {"command": {"path": "bash", "args": ["-c", "sudo x"], "env": {}}},
        "remote": {"url": "https://h.example/mcp",
                   "headers": {"Authorization": "Bearer abcdef123456"}},
    }}
    entries = _names(audit(data))
    assert discover(data).format == "context_servers (Zed)"
    assert entries["flat"].risk == Risk.CRITICAL
    assert entries["nested"].risk == Risk.CRITICAL
    assert entries["remote"].findings[0].category == "hardcoded-secret"


@pytest.mark.unit
def test_windsurf_server_url_and_references():
    data = {"mcpServers": {
        "remote": {"serverUrl": "http://h.example/mcp?api_key=abcdef123456"},
        "safe": {"command": "npx", "env": {"API_KEY": "${env:API_KEY}"},
                 "headers": {"Authorization": "Bearer ${file:/run/secret}"}},
    }}
    entries = _names(audit(data))
    categories = {f.category for f in entries["remote"].findings}
    assert categories == {"hardcoded-secret", "insecure-transport"}
    assert entries["safe"].findings == ()


@pytest.mark.unit
def test_continue_yaml_list(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "name: Block\nversion: 0.0.1\nschema: v1\n"
        "mcpServers:\n"
        "  - name: SQLite MCP\n    command: npx\n    args: [-y, mcp-sqlite, /db.db]\n"
        "  - name: Remote\n    type: sse\n    url: https://h.example/sse\n"
        "  - name: Remote\n    command: node\n"
        "    env:\n      SUPABASE_TOKEN: ${{ secrets.SUPABASE_TOKEN }}\n",
        encoding="utf-8")
    found = discover(load_config(path))
    assert found.format == "mcpServers list (Continue YAML)"
    assert list(found.servers) == ["SQLite MCP", "Remote", "Remote #2"]
    entries = _names(audit(load_config(path)))
    assert entries["SQLite MCP"].risk == Risk.MEDIUM  # "sqlite" -> database
    assert entries["Remote #2"].findings == ()  # ${{ secrets.X }} is a reference


@pytest.mark.unit
def test_invalid_yaml_is_a_format_error(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("mcpServers: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigFormatError):
        load_config(path)


@pytest.mark.unit
def test_combined_servers_and_tools_format_label():
    found = discover({"mcpServers": {}, "tools": []})
    assert found.format == "mcpServers (Claude Desktop / Cursor / Windsurf / Continue) + tools list"


# --- Rules files -----------------------------------------------------------


def _rules(tmp_path, content, suffix=".yaml"):
    path = tmp_path / f"rules{suffix}"
    path.write_text(content, encoding="utf-8")
    return load_ruleset(path)


@pytest.mark.unit
def test_custom_rule_extends_defaults(tmp_path):
    ruleset = _rules(tmp_path, (
        "rules:\n"
        "  - category: payments\n    risk: critical\n    keywords: [Refund, payout]\n"
        "    description: Moves money.\n"))
    data = {"tools": [{"name": "issue_refund"}, {"name": "run_shell"}]}
    entries = _names(audit(data, ruleset))
    assert entries["issue_refund"].findings[0].category == "payments"
    assert entries["issue_refund"].risk == Risk.CRITICAL
    assert entries["run_shell"].risk == Risk.CRITICAL  # default rules still active
    assert ruleset.describe("payments") == "Moves money."


@pytest.mark.unit
def test_disable_override_and_ignore(tmp_path):
    ruleset = _rules(tmp_path, json.dumps({
        "disable": ["network"],
        "rules": [{"category": "write-operation", "risk": "MEDIUM", "keywords": ["write"]}],
        "ignore": ["noisy_tool"],
    }), suffix=".json")
    data = {"tools": [{"name": "fetch_url"}, {"name": "write_file"},
                      {"name": "delete_file"}, {"name": "noisy_tool", "description": "exec"}]}
    entries = _names(audit(data, ruleset))
    assert entries["fetch_url"].risk == Risk.LOW
    assert entries["write_file"].risk == Risk.MEDIUM
    assert entries["delete_file"].risk == Risk.LOW  # overridden rule has no "delete"
    assert "noisy_tool" not in entries


@pytest.mark.unit
def test_extends_none_uses_only_custom_rules(tmp_path):
    ruleset = _rules(tmp_path, "extends: none\nrules:\n"
                               "  - {category: only, risk: LOW, keywords: [x]}\n")
    assert [r.category for r in ruleset.rules] == ["only"]


@pytest.mark.unit
@pytest.mark.parametrize("content", [
    "rules:\n  - {category: x, risk: EXTREME, keywords: [a]}\n",
    "rules:\n  - {category: 'Bad Name', risk: LOW, keywords: [a]}\n",
    "unknown_key: 1\n",
    "extends: something\n",
    "rules: [unclosed\n",
])
def test_invalid_rules_files(tmp_path, content):
    with pytest.raises(ConfigFormatError):
        _rules(tmp_path, content)


@pytest.mark.unit
def test_empty_rules_file_means_defaults(tmp_path):
    ruleset = _rules(tmp_path, "")
    assert len(ruleset.rules) == 6


@pytest.mark.unit
@pytest.mark.parametrize("name", ["add_observations", "save_note", "update_profile",
                                  "replace_text", "store_value"])
def test_more_mutating_verbs_are_high(name):
    (entry,) = audit({"tools": [{"name": name}]})
    assert entry.risk == Risk.HIGH
