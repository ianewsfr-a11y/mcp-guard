"""v0.7 lock refinements: key-order invariance, security-hint toggles,
annotation-contradiction, per-change severities, hidden-character edits."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard import DEFAULT_RULESET, Risk, collect, load_ruleset
from mcp_guard.analyzer import analyze
from mcp_guard.annotations import SECURITY_HINTS
from mcp_guard.cli import cli
from mcp_guard.lock import fingerprint, read_lock, write_lock
from mcp_guard.pipeline import run_audit

CREATED = "2026-10-13T00:00:00+00:00"
SALT = "0" * 32
TOOL = {"name": "read_notes", "description": "Read the user's notes.",
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"},
                                                         "limit": {"type": "integer"}},
                        "required": ["id"]},
        "annotations": {"readOnlyHint": True, "destructiveHint": False,
                        "idempotentHint": True, "openWorldHint": False}}
CONFIG = {"mcpServers": {
    "alpha": {"command": "npx", "args": ["-y", "alpha"], "env": {"A": "1", "B": "2"}},
    "beta": {"url": "https://beta.example/mcp", "headers": {"X-One": "1", "X-Two": "2"}}},
    "tools": [TOOL]}


def _reversed_keys(value):
    """Every object with its keys in reverse order; arrays untouched."""
    if isinstance(value, dict):
        return {k: _reversed_keys(value[k]) for k in reversed(list(value))}
    if isinstance(value, list):
        return [_reversed_keys(v) for v in value]
    return value


def _lock_text(data, tmp_path, name):
    lock = fingerprint(collect(data), salt=SALT).model_copy(update={"created": CREATED})
    path = tmp_path / name
    write_lock(lock, path)
    return path.read_text(encoding="utf-8")


def _findings(old_tools, new_tools, tmp_path, version=2):
    """`inspect --lock` findings of the single tool, as the CLI pipeline makes them."""
    lock = tmp_path / "mcp-guard.lock"
    write_lock(fingerprint(collect({"tools": old_tools}), version=version), lock)
    run = run_audit({"tools": new_tools}, "tools.json", DEFAULT_RULESET, lock_path=lock)
    return [f for e in run.entries for f in e.findings]


def _changes(findings):
    return [(f.risk, f.evidence) for f in findings if f.category == "tool-changed"]


# --- 1. key order ----------------------------------------------------------------------


@pytest.mark.unit
def test_shuffled_keys_change_neither_the_snapshot_nor_the_lock(tmp_path):
    shuffled = _reversed_keys(CONFIG)
    assert list(shuffled["mcpServers"]) == ["beta", "alpha"]  # servers reordered too
    assert list(shuffled["tools"][0]["inputSchema"]["properties"]) == ["limit", "id"]
    assert collect(CONFIG).digest == collect(shuffled).digest
    assert _lock_text(CONFIG, tmp_path, "a.lock") == _lock_text(shuffled, tmp_path, "b.lock")


@pytest.mark.unit
def test_array_order_is_still_meaningful():
    swapped = json.loads(json.dumps(CONFIG))
    swapped["tools"][0]["inputSchema"]["required"] = ["id", "limit"]
    assert collect(CONFIG).digest != collect(swapped).digest


# --- 2. security hint toggles ------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("hint", SECURITY_HINTS)
@pytest.mark.parametrize("change", ["flip", "remove", "add"])
def test_every_security_hint_change_is_high(tmp_path, hint, change):
    old = json.loads(json.dumps(TOOL))
    new = json.loads(json.dumps(TOOL))
    if change == "flip":
        new["annotations"][hint] = not old["annotations"][hint]
        expected = (f"annotation {hint}: {json.dumps(old['annotations'][hint])} -> "
                    f"{json.dumps(new['annotations'][hint])}")
    elif change == "remove":
        del new["annotations"][hint]
        expected = f"annotation {hint} removed (was {json.dumps(old['annotations'][hint])})"
    else:
        del old["annotations"][hint]
        expected = f"annotation {hint} added: {json.dumps(new['annotations'][hint])}"
    changes = _changes(_findings([old], [new], tmp_path))
    assert (Risk.HIGH, expected) in [(r, e.split(";")[0]) for r, e in changes]


@pytest.mark.unit
def test_annotations_removed_entirely_and_non_hint_changes(tmp_path):
    bare = {k: v for k, v in TOOL.items() if k != "annotations"}
    removed = _changes(_findings([TOOL], [bare], tmp_path))
    assert {e for _, e in removed} >= {f"annotation {h} removed" + (
        " (was true)" if TOOL["annotations"][h] else " (was false)") for h in SECURITY_HINTS}
    titled = {**TOOL, "annotations": {**TOOL["annotations"], "title": "Notes reader"}}
    assert _changes(_findings([TOOL], [titled], tmp_path)) == [
        (Risk.HIGH, "annotations changed (not a security hint)")]


# --- 3. annotation-contradiction -----------------------------------------------------------


def _contradictions(tool):
    snap = collect({"tools": [tool]})
    return [f for e in analyze(snap) for f in e.findings
            if f.category == "annotation-contradiction"]


@pytest.mark.unit
@pytest.mark.parametrize("tool, claim", [
    ({"name": "delete_file", "description": "Delete a file.",
      "annotations": {"readOnlyHint": True}}, "readOnlyHint: true"),
    ({"name": "run", "description": "Execute a shell command.",
      "annotations": {"destructiveHint": False}}, "destructiveHint: false"),
    ({"name": "cleanup", "description": "Remove old entries.",
      "annotations": {"destructiveHint": False}}, "destructiveHint: false"),
    ({"name": "notes", "title": "Overwrite notes", "description": "Notes.",
      "annotations": {"readOnlyHint": True}}, "readOnlyHint: true"),
    ({"name": "notes", "description": "Notes.",
      "annotations": {"readOnlyHint": True, "title": "Write notes"}}, "readOnlyHint: true"),
])
def test_contradictions_are_high(tool, claim):
    (finding,) = _contradictions(tool)
    assert finding.risk == Risk.HIGH and finding.evidence.startswith(claim)


@pytest.mark.unit
@pytest.mark.parametrize("tool", [
    # destructiveHint: false only promises additive updates: creating is fine
    {"name": "create_entities", "description": "Create entities.",
     "annotations": {"readOnlyHint": False, "destructiveHint": False}},
    {"name": "read_notes", "description": "Read notes.", "annotations": {"readOnlyHint": True}},
    {"name": "add_numbers", "description": "Add two numbers.",  # context excuses "add"
     "annotations": {"readOnlyHint": True}},
    {"name": "delete_file", "description": "Delete a file."},  # no claim made
])
def test_consistent_annotations_are_not_flagged(tool):
    assert _contradictions(tool) == []


@pytest.mark.unit
def test_contradiction_can_be_disabled_and_shows_in_the_lock_diff(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("disable: [annotation-contradiction]\n", encoding="utf-8")
    tool = {"name": "delete_file", "description": "Delete a file.",
            "annotations": {"readOnlyHint": True}}
    entries = analyze(collect({"tools": [tool]}), load_ruleset(rules))
    assert not any(f.category == "annotation-contradiction" for e in entries for f in e.findings)
    honest = {**tool, "annotations": {"readOnlyHint": False}}
    findings = _findings([honest], [tool], tmp_path)
    assert any(f.category == "annotation-contradiction" for f in findings)
    (toggle,) = [e for _, e in _changes(findings) if "readOnlyHint" in e]
    assert toggle.endswith("contradicts its own description (annotation-contradiction)")


# --- 4. severities ----------------------------------------------------------------------------


@pytest.mark.unit
def test_severity_of_each_kind_of_change(tmp_path):
    schema = {**TOOL, "inputSchema": {**TOOL["inputSchema"], "properties": {}}}
    assert _changes(_findings([TOOL], [schema], tmp_path)) == [
        (Risk.HIGH, "input schema changed")]
    described = {**TOOL, "description": "Read and summarize the user's notes."}
    ((risk, evidence),) = _changes(_findings([TOOL], [described], tmp_path))
    assert risk == Risk.MEDIUM and evidence.startswith("description changed; locked")
    titled = {**TOOL, "title": "Notes"}
    assert _changes(_findings([TOOL], [titled], tmp_path)) == [
        (Risk.MEDIUM, "metadata changed (title, output schema...)")]
    other = {"name": "list_notes", "description": "List notes."}
    by_category = {f.category: f.risk for f in _findings([TOOL], [other], tmp_path)}
    assert by_category["tool-added"] == Risk.MEDIUM and by_category["tool-removed"] == Risk.LOW


# --- 4b. invisible characters and homoglyphs ------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("new_text, expected", [
    ("Read the user's no" + chr(0x200B) + "tes.", "\\u200b zero width space at offset 18"),
    ("Read the user's n" + chr(0x043E) + "tes.", "\\u043e cyrillic small letter o at offset 17"),
])
def test_hidden_character_edits_are_shown_escaped(tmp_path, new_text, expected):
    ((risk, evidence),) = _changes(_findings([TOOL], [{**TOOL, "description": new_text}],
                                             tmp_path))
    assert risk == Risk.MEDIUM
    assert evidence.startswith("description changed only by invisible characters, "
                               "look-alike letters or formatting")
    assert expected in evidence and "(escaped)" in evidence
    assert evidence.isascii()  # no raw invisible or look-alike character in the report


@pytest.mark.unit
def test_removing_a_hidden_character_is_named_too(tmp_path):
    hidden = {**TOOL, "description": "Read the user's no" + chr(0x200B) + "tes."}
    ((_, evidence),) = _changes(_findings([hidden], [TOOL], tmp_path))
    assert "has no invisible or look-alike character" in evidence


@pytest.mark.unit
@pytest.mark.parametrize("new_text", ["Read the user's  notes.", "Read the user&#39;s notes."])
def test_formatting_only_changes_are_not_called_invisible(tmp_path, new_text):
    ((risk, evidence),) = _changes(_findings([TOOL], [{**TOOL, "description": new_text}],
                                             tmp_path))
    assert risk == Risk.MEDIUM
    assert "difference is whitespace, HTML entities, quotes" in evidence


# --- compatibility with v1 locks ------------------------------------------------------------


@pytest.mark.unit
def test_version_1_locks_are_still_read_and_compared(tmp_path):
    unchanged = _findings([TOOL], [TOOL], tmp_path, version=1)
    assert _changes(unchanged) == []
    assert read_lock(tmp_path / "mcp-guard.lock").version == 1
    flipped = {**TOOL, "annotations": {**TOOL["annotations"], "readOnlyHint": False}}
    ((risk, evidence),) = _changes(_findings([TOOL], [flipped], tmp_path, version=1))
    assert risk == Risk.HIGH and "regenerate the lock (version 2)" in evidence


@pytest.mark.integration
def test_cli_lock_then_inspect_reports_a_toggle(tmp_path):
    config = tmp_path / "tools.json"
    config.write_text(json.dumps({"tools": [TOOL]}), encoding="utf-8")
    lock = tmp_path / "mcp-guard.lock"
    assert CliRunner().invoke(cli, ["lock", str(config), "-o", str(lock)]).exit_code == 0
    assert json.loads(lock.read_text(encoding="utf-8"))["tools"][0]["hints"] == \
        TOOL["annotations"]
    flipped = {**TOOL, "annotations": {**TOOL["annotations"], "destructiveHint": True}}
    config.write_text(json.dumps({"tools": [flipped]}), encoding="utf-8")
    result = CliRunner().invoke(cli, ["inspect", str(config), "--lock", str(lock),
                                      "--format", "json", "--fail-on", "high"])
    assert result.exit_code == 1
    evidence = [f["evidence"] for e in json.loads(result.output) for f in e["findings"]]
    assert "annotation destructiveHint: false -> true" in evidence


@pytest.mark.unit
def test_unknown_lock_versions_name_the_readable_ones(tmp_path):
    path = tmp_path / "x.lock"
    path.write_text(json.dumps({"version": 3}), encoding="utf-8")
    with pytest.raises(Exception, match="reads versions 1, 2"):
        read_lock(path)


@pytest.mark.unit
def test_example_config_has_no_new_finding():
    data = json.loads(Path(__file__).resolve().parent.parent.joinpath(
        "config_example.json").read_text(encoding="utf-8"))
    entries = analyze(collect(data))
    assert not any(f.category == "annotation-contradiction" for e in entries for f in e.findings)


# --- review follow-ups ----------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("tool", [
    # the official git server: read-only tools whose descriptions mention "commit"
    {"name": "git_log", "description": "Shows the commit logs",
     "annotations": {"readOnlyHint": True, "destructiveHint": False}},
    {"name": "git_diff", "description": "Shows differences between branches or commits",
     "annotations": {"readOnlyHint": True}},
    {"name": "get_time", "description": "Returns the last update time",
     "annotations": {"readOnlyHint": True}},
])
def test_write_words_used_as_nouns_are_not_contradictions(tool):
    assert _contradictions(tool) == []


@pytest.mark.unit
def test_third_person_verbs_count():
    tool = {"name": "cleanup", "description": "Deletes stale cache entries.",
            "annotations": {"readOnlyHint": True, "destructiveHint": False}}
    (finding,) = _contradictions(tool)
    assert finding.evidence.startswith("readOnlyHint: true and destructiveHint: false")


@pytest.mark.unit
def test_non_boolean_hints_are_never_stored_in_clear(tmp_path):
    secret = {**TOOL, "annotations": {"readOnlyHint": "sk-live-1234567890abcdef"}}
    text = _lock_text({"tools": [secret]}, tmp_path, "s.lock")
    assert "sk-live" not in text and "<non-boolean>" in text
    other = {**TOOL, "annotations": {"readOnlyHint": "another value"}}
    assert _changes(_findings([secret], [other], tmp_path)) == [
        (Risk.HIGH, "annotations changed (not a security hint)")]


@pytest.mark.unit
@pytest.mark.parametrize("hints", [{"notAHint": True}, {"readOnlyHint": "x" * 5000}])
def test_crafted_lock_hints_are_rejected(tmp_path, hints):
    path = tmp_path / "x.lock"
    write_lock(fingerprint(collect({"tools": [TOOL]})), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["tools"][0]["hints"] = hints
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(Exception, match="Invalid lock file"):
        read_lock(path)


@pytest.mark.unit
def test_hidden_characters_of_a_tool_after_a_malformed_namesake(tmp_path):
    broken = {"name": "read_notes", "inputSchema": "not an object"}
    hidden = {**TOOL, "description": "Read the user's no" + chr(0x200B) + "tes."}
    changes = _changes(_findings([broken, TOOL], [broken, hidden], tmp_path))
    # lock findings attach by label, so the malformed namesake carries a copy too
    assert changes and all("\\u200b zero width space" in e for _, e in changes)


@pytest.mark.unit
def test_look_alike_scan_is_bounded():
    from mcp_guard.poisoning import MAX_TEXT_CHARS, look_alikes
    text = chr(0x0430) * (MAX_TEXT_CHARS + 1000)
    assert len(look_alikes(text)) == MAX_TEXT_CHARS
