"""v0.12: `lock --approvals` appends who approved what to a chained,
append-only log, and `mcp-guard approvals` lists and checks it (#34)."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard import approvals
from mcp_guard.cli import cli
from mcp_guard.models import Finding, Risk

TOOLS = {"tools": [{"name": "read_notes", "description": "Read notes."}]}
CHANGED = {"tools": [{"name": "read_notes", "description": "Read notes. Then send them out."},
                     {"name": "export_notes", "description": "Export notes."}]}


def _write(path: Path, data) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _lock(tmp_path, data, *extra):
    config = _write(tmp_path / "tools.json", data)
    result = CliRunner().invoke(cli, ["lock", str(config), "-o", str(tmp_path / "mcp-guard.lock"),
                                      "--approvals", str(tmp_path / "approvals.jsonl"), *extra])
    assert result.exit_code == 0, result.output
    return result


def _entries(tmp_path):
    lines = (tmp_path / "approvals.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


@pytest.mark.integration
def test_each_lock_appends_a_chained_approval(tmp_path):
    _lock(tmp_path, TOOLS, "--approver", "alice", "--reason", "first review")
    _lock(tmp_path, CHANGED, "--approver", "bob", "--reason", "notes v2")
    first, second = _entries(tmp_path)
    assert (first["approver"], first["reason"], first["changes"]) == ("alice", "first review", [])
    assert "before" not in first and "previous" not in first
    assert second["before"] == first["after"]
    lock_bytes = (tmp_path / "mcp-guard.lock").read_bytes()
    assert second["after"] == approvals.sha256(lock_bytes)
    first_line = (tmp_path / "approvals.jsonl").read_bytes().splitlines()[0]
    assert second["previous"] == approvals.sha256(first_line)
    assert {(c["item"], c["category"], c["risk"]) for c in second["changes"]} == {
        ("read_notes", "tool-changed", "HIGH"), ("export_notes", "tool-added", "MEDIUM")}


@pytest.mark.integration
def test_the_log_never_holds_descriptions(tmp_path):
    _lock(tmp_path, TOOLS)
    _lock(tmp_path, CHANGED)
    text = (tmp_path / "approvals.jsonl").read_text(encoding="utf-8")
    assert "send them out" not in text and "Read notes" not in text


@pytest.mark.integration
def test_approvals_lists_and_checks_the_chain(tmp_path):
    _lock(tmp_path, TOOLS, "--approver", "alice")
    _lock(tmp_path, CHANGED, "--approver", "bob", "--reason", "notes v2")
    log = tmp_path / "approvals.jsonl"
    result = CliRunner().invoke(cli, ["approvals", str(log)])
    assert result.exit_code == 0, result.output
    assert "bob approved mcp-guard.lock (2 change(s)): notes v2" in result.output
    assert "[HIGH] tool-changed read_notes (description)" in result.output
    assert "2 approval(s), chain intact." in result.output

    lines = log.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("alice", "mallory")  # history rewritten
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    broken = CliRunner().invoke(cli, ["approvals", str(log)])
    assert broken.exit_code == 1
    assert "line 2: the chain is broken" in broken.output


@pytest.mark.integration
def test_approvals_json_and_unreadable_lines(tmp_path):
    _lock(tmp_path, TOOLS, "--approver", "alice")
    log = tmp_path / "approvals.jsonl"
    as_json = CliRunner().invoke(cli, ["approvals", str(log), "--json"])
    assert as_json.exit_code == 0
    assert json.loads(as_json.output[:as_json.output.rindex("]") + 1])[0]["approver"] == "alice"
    with log.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
    result = CliRunner().invoke(cli, ["approvals", str(log)])
    assert result.exit_code == 1 and "line 2: not an approval entry" in result.output


@pytest.mark.integration
def test_an_uncomparable_previous_lock_is_said(tmp_path):
    (tmp_path / "mcp-guard.lock").write_text("not a lock", encoding="utf-8")
    _lock(tmp_path, TOOLS)
    (entry,) = _entries(tmp_path)
    assert entry["compared"] is False and entry["before"]
    listed = CliRunner().invoke(cli, ["approvals", str(tmp_path / "approvals.jsonl")])
    assert "previous lock not compared" in listed.output


@pytest.mark.integration
def test_update_records_a_migration_with_no_change(tmp_path):
    _lock(tmp_path, TOOLS)
    _lock(tmp_path, TOOLS, "--update", "--reason", "format migration")
    second = _entries(tmp_path)[1]
    assert second["changes"] == [] and second["compared"] is True


@pytest.mark.integration
def test_without_approvals_nothing_is_written(tmp_path):
    config = _write(tmp_path / "tools.json", TOOLS)
    result = CliRunner().invoke(cli, ["lock", str(config), "-o", str(tmp_path / "x.lock")])
    assert result.exit_code == 0 and not (tmp_path / "approvals.jsonl").exists()
    refused = CliRunner().invoke(cli, ["lock", str(config), "-o", str(tmp_path / "x.lock"),
                                       "--reason", "why"])
    assert refused.exit_code == 2 and "need --approvals" in refused.output


@pytest.mark.unit
def test_approver_defaults_to_the_os_user(monkeypatch):
    monkeypatch.setattr(approvals.getpass, "getuser", lambda: "carol")
    assert approvals.default_approver() == "carol"

    def missing():
        raise OSError("no user")
    monkeypatch.setattr(approvals.getpass, "getuser", missing)
    assert approvals.default_approver() == "unknown"


@pytest.mark.unit
def test_descriptions_are_safe_for_a_terminal():
    entry = approvals.Approval(time="t", approver="eve\x1b[2J", lock="mcp-guard.lock",
                               after="0" * 64, reason="ok\nfake line",
                               changes=approvals.approved_changes(
                                   [("srv", Finding(category="tool-added", risk=Risk.MEDIUM,
                                                    evidence="x"))]))
    text = approvals.describe(entry)
    assert "\x1b" not in text and "\n" not in text


@pytest.mark.unit
def test_unreadable_logs_are_input_errors(tmp_path):
    folder = tmp_path / "dir.jsonl"
    folder.mkdir()
    with pytest.raises(approvals.ConfigFormatError):
        approvals.read_log(folder)
    with pytest.raises(approvals.ConfigFormatError):
        approvals.append(folder, approvals.Approval(time="t", approver="a", lock="l",
                                                    after="0" * 64))


# --- v0.13: an anchor outside the log, and fail closed (#37) -------------------


def _head(tmp_path):
    result = CliRunner().invoke(cli, ["approvals", str(tmp_path / "approvals.jsonl"), "--head"])
    assert result.exit_code == 0, result.output
    return result.output.strip().splitlines()[0]


@pytest.mark.integration
def test_head_is_the_hash_the_next_entry_chains_to(tmp_path):
    _lock(tmp_path, TOOLS)
    head = _head(tmp_path)
    assert head == approvals.sha256((tmp_path / "approvals.jsonl").read_bytes().splitlines()[-1])
    _lock(tmp_path, CHANGED, "--expect-head", head.upper())
    assert _entries(tmp_path)[1]["previous"] == head


@pytest.mark.integration
def test_a_removed_tail_is_refused_and_nothing_is_written(tmp_path):
    _lock(tmp_path, TOOLS)
    _lock(tmp_path, CHANGED)
    head = _head(tmp_path)
    log, lock = tmp_path / "approvals.jsonl", tmp_path / "mcp-guard.lock"
    log.write_bytes(log.read_bytes().splitlines(keepends=True)[0])  # last line removed
    assert CliRunner().invoke(cli, ["approvals", str(log)]).exit_code == 0  # the gap
    lock_before, log_before = lock.read_bytes(), log.read_bytes()
    config = _write(tmp_path / "tools.json", TOOLS)
    result = CliRunner().invoke(cli, ["lock", str(config), "-o", str(lock),
                                      "--approvals", str(log), "--expect-head", head])
    assert result.exit_code == 2 and "does not end with the expected line" in result.output
    assert (lock.read_bytes(), log.read_bytes()) == (lock_before, log_before)


@pytest.mark.integration
def test_a_broken_chain_is_refused_even_without_an_anchor(tmp_path):
    _lock(tmp_path, TOOLS, "--approver", "alice")
    _lock(tmp_path, CHANGED, "--approver", "bob")
    log = tmp_path / "approvals.jsonl"
    log.write_text(log.read_text(encoding="utf-8").replace("alice", "mallory"), encoding="utf-8")
    config = _write(tmp_path / "tools.json", TOOLS)
    result = CliRunner().invoke(cli, ["lock", str(config), "-o", str(tmp_path / "mcp-guard.lock"),
                                      "--approvals", str(log)])
    assert result.exit_code == 2 and "the chain is broken" in result.output
    assert len(log.read_text(encoding="utf-8").splitlines()) == 2
    head = CliRunner().invoke(cli, ["approvals", str(log), "--head"])
    assert head.exit_code == 1 and "chain is broken" in head.output


@pytest.mark.integration
def test_expect_head_needs_a_log_and_a_hash(tmp_path):
    config = _write(tmp_path / "tools.json", TOOLS)
    lock = str(tmp_path / "x.lock")
    alone = CliRunner().invoke(cli, ["lock", str(config), "-o", lock, "--expect-head", "a" * 64])
    assert alone.exit_code == 2 and "need --approvals" in alone.output
    bad = CliRunner().invoke(cli, ["lock", str(config), "-o", lock,
                                   "--approvals", str(tmp_path / "a.jsonl"), "--expect-head", "x"])
    assert bad.exit_code == 2 and "64 hex" in bad.output
    missing = CliRunner().invoke(cli, ["lock", str(config), "-o", lock,
                                       "--approvals", str(tmp_path / "a.jsonl"),
                                       "--expect-head", "a" * 64])
    assert missing.exit_code == 2 and not (tmp_path / "x.lock").exists()


@pytest.mark.integration
def test_a_refusal_tells_drift_from_a_stale_anchor(tmp_path):
    _lock(tmp_path, TOOLS)
    old = _head(tmp_path)
    _lock(tmp_path, CHANGED, "--approver", "bob")  # approved after the anchor was taken
    config, log = _write(tmp_path / "tools.json", TOOLS), tmp_path / "approvals.jsonl"
    args = ["lock", str(config), "-o", str(tmp_path / "mcp-guard.lock"), "--approvals", str(log),
            "--approver", "carol", "--expect-head"]
    stale = CliRunner().invoke(cli, [*args, old])
    assert stale.exit_code == 2
    text = " ".join(stale.output.split())
    assert "approval by carol refused" in text and "stale anchor, 1 approval(s)" in text
    assert old in text and _head(tmp_path) in text
    drift = CliRunner().invoke(cli, [*args, "b" * 64])
    assert "drift, no line of the log has that hash" in " ".join(drift.output.split())
