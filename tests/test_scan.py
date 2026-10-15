"""`scan`: client config locations, dedup across configs, output formats."""

from __future__ import annotations

import json
import re
import socket
import subprocess
from pathlib import Path

import jsonschema
import pytest
from click.testing import CliRunner

from mcp_guard import cli as cli_module
from mcp_guard.cli import cli
from mcp_guard.clients import Location, locations
from mcp_guard.rules import DEFAULT_RULESET
from mcp_guard.scan import MAX_CONFIG_BYTES, scan
from mcp_guard.scan_report import scan_to_json, scan_to_sarif, shown_path

SCHEMA = json.loads((Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json")
                    .read_text(encoding="utf-8"))
SHELL = {"command": "npx", "args": ["-y", "mcp-shell-server"]}  # command-execution: CRITICAL
MEMORY = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]}
SECRET = {"command": "npx", "args": ["-y", "some-server"],
          "env": {"API_KEY": "sk-live-0123456789abcdef0123"}}


def _paths(found: tuple[Location, ...]) -> dict[str, list[str]]:
    by_client: dict[str, list[str]] = {}
    for loc in found:
        by_client.setdefault(loc.client, []).append(loc.path.as_posix())
    return by_client


# --------------------------------------------------------------------------- #
# Locations
# --------------------------------------------------------------------------- #


def test_windows_locations_follow_appdata():
    home, cwd = Path("C:/Users/ana"), Path("D:/work/repo")
    found = _paths(locations(home, cwd, {"APPDATA": "E:/Roaming"}, "Windows"))
    storage = "E:/Roaming/Code/User/globalStorage"
    assert found["Claude Desktop"] == ["E:/Roaming/Claude/claude_desktop_config.json"]
    assert found["Claude Code"] == ["C:/Users/ana/.claude.json", "D:/work/repo/.mcp.json"]
    assert found["Cursor"] == ["C:/Users/ana/.cursor/mcp.json", "D:/work/repo/.cursor/mcp.json"]
    assert found["VS Code"] == ["E:/Roaming/Code/User/mcp.json",
                                "C:/Users/ana/.copilot/mcp-config.json",
                                "D:/work/repo/.vscode/mcp.json"]
    assert found["Windsurf"] == ["E:/Roaming/devin/mcp_config.json",
                                 "C:/Users/ana/.codeium/windsurf/mcp_config.json"]
    assert found["Zed"] == ["E:/Roaming/Zed/settings.json"]
    assert found["Continue"] == ["C:/Users/ana/.continue/config.yaml"]
    assert found["Cline"] == [
        "C:/Users/ana/.cline/data/settings/cline_mcp_settings.json",
        f"{storage}/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"]
    assert found["Roo Code"] == [f"{storage}/rooveterinaryinc.roo-cline/settings/mcp_settings.json"]


def test_windows_without_an_absolute_appdata_uses_the_roaming_folder():
    for env in ({}, {"APPDATA": "Roaming"}):
        found = _paths(locations(Path("C:/Users/ana"), Path("D:/r"), env, "Windows"))
        assert found["Claude Desktop"] == [
            "C:/Users/ana/AppData/Roaming/Claude/claude_desktop_config.json"]


def test_macos_locations_use_application_support():
    found = _paths(locations(Path("/Users/ana"), Path("/src/repo"), {}, "Darwin"))
    support = "/Users/ana/Library/Application Support"
    assert found["Claude Desktop"] == [f"{support}/Claude/claude_desktop_config.json"]
    assert found["VS Code"][0] == f"{support}/Code/User/mcp.json"
    assert found["Windsurf"][0] == "/Users/ana/.config/devin/mcp_config.json"
    assert found["Zed"] == ["/Users/ana/.config/zed/settings.json"]


def test_linux_locations_follow_xdg_config_home():
    env = {"XDG_CONFIG_HOME": "/data/cfg"}
    found = _paths(locations(Path("/home/ana"), Path("/src/repo"), env, "Linux"))
    assert found["VS Code"][0] == "/data/cfg/Code/User/mcp.json"
    assert found["Windsurf"][0] == "/data/cfg/devin/mcp_config.json"
    assert found["Zed"] == ["/data/cfg/zed/settings.json"]
    assert found["Cline"][1].startswith("/data/cfg/Code/User/globalStorage/")
    relative = _paths(locations(Path("/home/ana"), Path("/r"), {"XDG_CONFIG_HOME": "cfg"},
                                "Linux"))
    assert relative["VS Code"][0] == "/home/ana/.config/Code/User/mcp.json"  # must be absolute


def test_copilot_home_moves_the_vscode_user_file():
    found = _paths(locations(Path("/home/ana"), Path("/r"), {"COPILOT_HOME": "/opt/cp"},
                             "Linux"))
    assert "/opt/cp/mcp-config.json" in found["VS Code"]


def test_unconfirmed_paths_are_marked_not_verified():
    def unverified(system):
        found = locations(Path("/home/ana"), Path("/r"), {}, system)
        assert all(loc.source.startswith("not verified") for loc in found if not loc.verified)
        assert all(loc.source.startswith("https://") for loc in found if loc.verified)
        return {loc.path.as_posix().rsplit("/", 1)[-1] + f" ({loc.client})"
                for loc in found if not loc.verified}

    linux = unverified("Linux")
    assert linux == {"claude_desktop_config.json (Claude Desktop)", "mcp.json (VS Code)",
                     "mcp_config.json (Windsurf)", "cline_mcp_settings.json (Cline)",
                     "mcp_settings.json (Roo Code)"}
    assert unverified("Windows") == (linux - {"claude_desktop_config.json (Claude Desktop)"}
                                     ) | {".claude.json (Claude Code)"}


def test_a_path_is_listed_once_when_cwd_is_home():
    found = locations(Path("/home/ana"), Path("/home/ana"), {}, "Linux")
    paths = [loc.path for loc in found]
    assert len(paths) == len(set(paths))


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #


def _write(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _loc(client: str, path: Path, reader: str = "config") -> Location:
    return Location(client, path, "user", True, "https://example.test", reader)  # type: ignore[arg-type]


def test_same_server_in_two_configs_is_audited_once(tmp_path):
    cursor = _write(tmp_path / "cursor.json", {"mcpServers": {"shell": SHELL, "memory": MEMORY}})
    windsurf = _write(tmp_path / "windsurf.json",
                      {"mcpServers": {"bash-tool": {**SHELL, "disabled": False}}})
    result = scan((_loc("Cursor", cursor), _loc("Windsurf", windsurf)), DEFAULT_RULESET)
    assert len(result.servers) == 2
    shell = next(s for s in result.servers if s.entry.name == "shell")
    assert [(o.client, o.name) for o in shell.locations] == [("Cursor", "shell"),
                                                            ("Windsurf", "bash-tool")]
    assert result.configs[1].servers == (("bash-tool", shell.id),)


def test_servers_that_differ_in_env_are_not_merged(tmp_path):
    a = _write(tmp_path / "a.json", {"mcpServers": {"x": SECRET}})
    b = _write(tmp_path / "b.json", {"mcpServers": {"x": {**SECRET, "env": {}}}})
    assert len(scan((_loc("Cursor", a), _loc("Windsurf", b)), DEFAULT_RULESET).servers) == 2


def test_malformed_entries_are_never_merged(tmp_path):
    a = _write(tmp_path / "a.json", {"mcpServers": {"x": {"command": 3}}})
    b = _write(tmp_path / "b.json", {"mcpServers": {"x": {"command": 3}}})
    result = scan((_loc("Cursor", a), _loc("Windsurf", b)), DEFAULT_RULESET)
    assert len(result.servers) == 2
    assert all(s.entry.findings[0].category == "malformed-entry" for s in result.servers)


def test_claude_code_user_and_project_sections(tmp_path):
    path = _write(tmp_path / ".claude.json", {
        "oauthAccount": {"emailAddress": "not read"},
        "mcpServers": {"memory": MEMORY},
        "projects": {"/src/app": {"mcpServers": {"shell": SHELL}},
                     "/src/empty": {"mcpServers": {}}, "/src/other": {"history": []}}})
    result = scan((_loc("Claude Code", path, "claude-code"),), DEFAULT_RULESET)
    assert [(c.section, c.status) for c in result.configs] == [("user", "ok"),
                                                              ("project /src/app", "ok")]
    assert "not read" not in scan_to_json(result)


def test_claude_code_without_servers(tmp_path):
    path = _write(tmp_path / ".claude.json", {"projects": []})
    result = scan((_loc("Claude Code", path, "claude-code"),), DEFAULT_RULESET)
    assert [c.status for c in result.configs] == ["no-servers"]


def test_unreadable_too_large_and_serverless_configs(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{nope", encoding="utf-8")
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))
    zed = _write(tmp_path / "settings.json", {"theme": "One Dark"})
    missing = tmp_path / "missing.json"
    result = scan(tuple(_loc("Zed", p) for p in (broken, big, zed, missing)), DEFAULT_RULESET)
    assert [c.status for c in result.configs] == ["error", "error", "no-servers"]
    assert "MB" in (result.configs[1].error or "")
    assert result.servers == ()


def test_deeply_nested_config_is_an_error_not_a_crash(tmp_path):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    result = scan((_loc("Cursor", deep),), DEFAULT_RULESET)
    assert result.configs[0].status == "error"


def test_shown_path_hides_the_home_directory(tmp_path):
    assert shown_path(tmp_path / "a" / "b.json", tmp_path) == str(Path("~/a/b.json"))
    assert shown_path(Path("/elsewhere/x.json"), tmp_path) == str(Path("/elsewhere/x.json"))


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #


def test_sarif_is_valid_and_has_one_result_per_finding(tmp_path):
    cursor = _write(tmp_path / "cursor.json",
                    {"mcpServers": {"shell": SHELL, "keys": SECRET, "memory": MEMORY}})
    vscode = _write(tmp_path / "mcp.json", {"servers": {"shell": SHELL}})
    result = scan((_loc("Cursor", cursor), _loc("VS Code", vscode)), DEFAULT_RULESET)
    report = scan_to_sarif(result, DEFAULT_RULESET)
    jsonschema.Draft4Validator(SCHEMA).validate(report)
    run = report["runs"][0]
    findings = [f for s in result.servers for f in s.entry.findings]
    assert len(run["results"]) == len(findings) > 0
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["mcp-guard/command-execution"] == "error"  # CRITICAL
    assert levels["mcp-guard/hardcoded-secret"] == "error"
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert set(levels) <= rule_ids
    shell = next(r for r in run["results"] if r["ruleId"] == "mcp-guard/command-execution")
    uri = shell["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == cursor.as_uri()
    assert shell["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"] == \
        vscode.as_uri()
    assert shell["message"]["text"].startswith("Cursor: server 'shell'")


def test_sarif_without_any_config_is_valid():
    report = scan_to_sarif(scan((), DEFAULT_RULESET), DEFAULT_RULESET)
    jsonschema.Draft4Validator(SCHEMA).validate(report)
    assert report["runs"][0]["results"] == []


def test_sarif_locates_the_server_line(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{\n  "mcpServers": {\n    "shell": {"command": "mcp-shell-server"}\n  }\n}',
                    encoding="utf-8")
    report = scan_to_sarif(scan((_loc("Cursor", path),), DEFAULT_RULESET), DEFAULT_RULESET)
    lines = {r["locations"][0]["physicalLocation"]["region"]["startLine"]
             for r in report["runs"][0]["results"]}
    assert lines == {3}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A fake home directory and project, with no network and no process."""
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.chdir(project)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("scan must not start a process or open a connection")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    return home, project


def _where(home: Path, project: Path, client: str, scope: str = "user") -> Path:
    found = locations(home, project, {"APPDATA": str(home / "AppData" / "Roaming")},
                      cli_module._system())
    return next(loc.path for loc in found if loc.client == client and loc.scope == scope)


def _run(*args: str):
    return CliRunner().invoke(cli, ["scan", *args])


def test_cli_scan_without_any_config_exits_0(machine):
    result = _run()
    assert result.exit_code == 0, result.output
    assert "No MCP client configuration found" in result.output


def test_cli_scan_without_high_finding_exits_0(machine):
    home, project = machine
    _write(_where(home, project, "Cursor"), {"mcpServers": {"memory": MEMORY}})
    result = _run()
    assert result.exit_code == 0, result.output
    assert "Cursor" in result.output and "memory" in result.output


def test_cli_scan_exit_code_follows_the_highest_risk(machine):
    home, project = machine
    path = _where(home, project, "Cursor")
    _write(path, {"mcpServers": {"remote": {"url": "http://mcp.example.test/mcp"}}})
    assert "MEDIUM" in _run().output and _run().exit_code == 0  # insecure-transport
    _write(path, {"mcpServers": {"keys": SECRET}})
    assert _run().exit_code == 1  # hardcoded-secret: HIGH
    assert _run("--fail-on", "critical").exit_code == 0


def test_cli_scan_groups_by_client_and_exits_1_on_high(machine):
    home, project = machine
    _write(_where(home, project, "Cursor"), {"mcpServers": {"shell": SHELL}})
    _write(_where(home, project, "Windsurf"), {"mcpServers": {"shell": SHELL}})
    _write(_where(home, project, "Claude Code", "project"), {"mcpServers": {"memory": MEMORY}})
    result = _run()
    assert result.exit_code == 1, result.output
    out = result.output
    assert out.index("Claude Code") < out.index("Cursor") < out.index("Windsurf")
    assert "same server as Cursor > shell" in out
    assert out.count("command-execution") == 1
    assert _run("--fail-on", "none").exit_code == 0


def test_cli_scan_json(machine, tmp_path):
    home, project = machine
    _write(_where(home, project, "Cursor"), {"mcpServers": {"shell": SHELL}})
    _write(_where(home, project, "VS Code", "project"), {"servers": {"sh": SHELL}})
    out = tmp_path / "scan.json"
    assert _run("--json", "-o", str(out)).exit_code == 1
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"] == {"configs": 2, "unreadable": 0, "server_entries": 2,
                                 "distinct_servers": 1,
                                 "findings": 1, "highest_risk": "CRITICAL"}
    assert [c["client"] for c in report["configs"]] == ["Cursor", "VS Code"]
    server = report["servers"][0]
    assert [o["name"] for o in server["locations"]] == ["shell", "sh"]
    assert report["configs"][1]["servers"] == [{"name": "sh", "server": server["id"]}]


def test_cli_scan_sarif_file_is_valid(machine, tmp_path):
    home, project = machine
    _write(_where(home, project, "Cursor"), {"mcpServers": {"shell": SHELL}})
    out = tmp_path / "scan.sarif"
    assert _run("--sarif", "-o", str(out)).exit_code == 1
    jsonschema.Draft4Validator(SCHEMA).validate(json.loads(out.read_text(encoding="utf-8")))


def test_cli_scan_rejects_json_and_sarif_together(machine):
    assert _run("--json", "--sarif").exit_code == 2


def test_cli_scan_reports_an_unreadable_config_and_goes_on(machine):
    home, project = machine
    path = _where(home, project, "Cursor")
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")
    _write(_where(home, project, "Windsurf"), {"mcpServers": {"memory": MEMORY}})
    result = _run()
    assert result.exit_code == 0
    assert "not read" in result.output and "memory" in result.output


@pytest.mark.parametrize("args", [(), ("--json",), ("--sarif",)])
def test_outputs_never_claim_safety(machine, args):
    home, project = machine
    _write(_where(home, project, "Cursor"), {"mcpServers": {"memory": MEMORY, "shell": SHELL}})
    _write(_where(home, project, "Windsurf"), {"mcpServers": {}})
    output = _run(*args).output
    assert not re.search(r"\b(safe|secure)\b", output, re.IGNORECASE)


def test_scan_never_prints_a_secret(machine):
    home, project = machine
    _write(_where(home, project, "Cursor"), {"mcpServers": {"keys": SECRET}})
    for args in ((), ("--json",), ("--sarif",)):
        assert "0123456789abcdef0123" not in _run(*args).output


def test_system_names(monkeypatch):
    for name, expected in (("Windows", "Windows"), ("Darwin", "Darwin"),
                           ("Linux", "Linux"), ("FreeBSD", "Linux")):
        monkeypatch.setattr(cli_module.platform, "system", lambda n=name: n)
        assert cli_module._system() == expected


# --------------------------------------------------------------------------- #
# Review follow-ups: shapes, symlinks, hostile files
# --------------------------------------------------------------------------- #


def test_disabled_and_enabled_copies_are_not_merged(tmp_path):
    a = _write(tmp_path / "a.json", {"mcpServers": {"shell": SHELL}})
    b = _write(tmp_path / "b.json", {"mcpServers": {"shell": {**SHELL, "disabled": True}}})
    assert len(scan((_loc("Cursor", a), _loc("Windsurf", b)), DEFAULT_RULESET).servers) == 2


def test_zed_and_continue_formats_through_scan(tmp_path):
    zed = _write(tmp_path / "settings.json", {"theme": "x", "context_servers": {
        "shell": {"command": "npx", "args": ["-y", "mcp-shell-server"], "env": {}}}})
    cont = tmp_path / "config.yaml"
    cont.write_text("name: me\nmcpServers:\n  - name: shell\n    command: npx\n"
                    "    args: [-y, mcp-shell-server]\n", encoding="utf-8")
    result = scan((_loc("Zed", zed), _loc("Continue", cont)), DEFAULT_RULESET)
    assert [c.status for c in result.configs] == ["ok", "ok"]
    assert len(result.servers) == 1 and len(result.servers[0].locations) == 2


def test_a_server_key_of_the_wrong_type_is_an_error(tmp_path):
    path = _write(tmp_path / "mcp.json", {"mcpServers": "oops"})
    config = scan((_loc("Cursor", path),), DEFAULT_RULESET).configs[0]
    assert (config.status, config.error) == ("error", "`mcpServers` is not an object")


def test_a_directory_at_a_config_path_is_skipped(tmp_path):
    (tmp_path / "mcp.json").mkdir()
    assert scan((_loc("Cursor", tmp_path / "mcp.json"),), DEFAULT_RULESET).configs == ()


def test_an_unexpected_error_in_one_config_does_not_stop_the_scan(tmp_path, monkeypatch):
    from mcp_guard import scan as scan_module
    a = _write(tmp_path / "a.json", {"mcpServers": {"x": MEMORY}})
    b = _write(tmp_path / "b.json", {"mcpServers": {"y": MEMORY}})
    real = scan_module.collect

    def flaky(data, source):
        if source == str(a):
            raise TypeError("boom")
        return real(data, source)

    monkeypatch.setattr(scan_module, "collect", flaky)
    result = scan((_loc("Cursor", a), _loc("Windsurf", b)), DEFAULT_RULESET)
    assert [(c.status, c.error) for c in result.configs] == [
        ("error", "internal error (TypeError)"), ("ok", None)]


def test_project_symlinks_are_not_followed(tmp_path):
    secret = _write(tmp_path / "private.json", {"mcpServers": {"x": MEMORY}})
    repo = tmp_path / "repo"
    repo.mkdir()
    link = repo / ".mcp.json"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symbolic links are not allowed here")
    project = Location("Claude Code", link, "project", True, "https://example.test")
    user = Location("Cursor", link, "user", True, "https://example.test")
    result = scan((project,), DEFAULT_RULESET)
    assert result.configs[0].status == "error" and "symbolic link" in result.configs[0].error
    assert scan((user,), DEFAULT_RULESET).configs[0].status == "ok"  # the user's own choice


def test_sarif_lines_follow_the_claude_code_project(tmp_path):
    path = tmp_path / ".claude.json"
    path.write_text(json.dumps({
        "mcpServers": {"shell": SHELL},
        "projects": {"/src/app": {"mcpServers": {"shell": {**SHELL, "env": {"A": "1"}}}}},
    }, indent=2), encoding="utf-8")
    result = scan((_loc("Claude Code", path, "claude-code"),), DEFAULT_RULESET)
    report = scan_to_sarif(result, DEFAULT_RULESET)
    lines = [r["locations"][0]["physicalLocation"]["region"]["startLine"]
             for r in report["runs"][0]["results"]]
    text = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and lines[0] < lines[1]
    assert all('"shell"' in text[line - 1] for line in lines)


def test_cli_scan_rejects_output_without_a_format(machine, tmp_path):
    assert _run("-o", str(tmp_path / "x.txt")).exit_code == 2


def test_cli_scan_warns_about_unread_configs(machine, tmp_path):
    home, project = machine
    path = _where(home, project, "Cursor")
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")
    out = tmp_path / "scan.json"
    result = _run("--json", "-o", str(out))
    assert "1 config(s) could not be read" in result.output
    assert json.loads(out.read_text(encoding="utf-8"))["summary"]["unreadable"] == 1


def test_emoji_codes_in_names_are_printed_as_written(machine):
    home, project = machine
    _write(_where(home, project, "Cursor"), {"mcpServers": {":smile:": MEMORY}})
    assert ":smile:" in _run().output


@pytest.mark.parametrize("unit", ["/*a", chr(92) + '"', '"a' + chr(92)],
                         ids=["open-comments", "escaped-quotes", "open-strings"])
def test_hostile_jsonc_is_read_in_linear_time(tmp_path, unit):
    import time
    path = tmp_path / "mcp.json"
    path.write_text(unit * 200_000, encoding="utf-8")
    start = time.monotonic()
    result = scan((_loc("Cursor", path),), DEFAULT_RULESET)
    assert result.configs[0].status == "error"
    assert time.monotonic() - start < 10  # quadratic: several minutes


def test_locate_is_linear_on_blank_lines():
    import time

    from mcp_guard.sarif import locate
    start = time.monotonic()
    assert locate("{}" + "\n" * 400_000, "x") == 1
    assert time.monotonic() - start < 10


def test_highest_risk_is_null_without_findings(tmp_path):
    path = _write(tmp_path / "a.json", {"mcpServers": {"m": {"command": "node", "args": []}}})
    result = scan((_loc("Cursor", path),), DEFAULT_RULESET)
    assert result.servers[0].entry.findings == ()
    assert json.loads(scan_to_json(result))["summary"]["highest_risk"] is None
