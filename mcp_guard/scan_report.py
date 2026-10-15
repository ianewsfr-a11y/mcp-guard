"""`scan` output: a terminal report grouped by client then by server, a JSON
report, and a SARIF 2.1.0 log. Wording stays factual: a server without a
finding has "no finding", nothing more is claimed about it."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape

from . import __version__
from .clients import CLIENTS
from .models import Finding
from .renderer import RISK_STYLES
from .rules import RuleSet
from .sarif import INFORMATION_URI, SARIF_SCHEMA, finding_result, locate, rule_descriptors
from .scan import ConfigResult, Occurrence, ScannedServer, ScanResult
from .text import printable

console = Console(emoji=False)  # a server named :smile: stays as written


def shown_path(path: Path, home: Path | None = None) -> str:
    """The path with the home directory as `~`, so reports do not repeat a user name."""
    home = home or Path.home()
    try:
        return str(Path("~") / path.relative_to(home))
    except ValueError:
        return str(path)


def _where(o: Occurrence) -> str:
    section = f" [{o.section}]" if o.section else ""
    return f"{o.client} > {o.name} ({shown_path(o.path)}{section})"


# --------------------------------------------------------------------------- #
# Terminal
# --------------------------------------------------------------------------- #


def _finding_line(f: Finding) -> str:
    return (f"      [{RISK_STYLES[f.risk]}]{f.risk.name}[/] "
            f"{escape(printable(f.category, 60))}: {escape(printable(f.evidence, 300))}")


def _server_lines(name: str, server: ScannedServer, config: ConfigResult) -> list[str]:
    label = escape(printable(name, 80))
    first = server.locations[0]
    if (first.path, first.section, first.name) != (config.location.path, config.section, name):
        where = escape(printable(_where(first), 200))
        return [f"    [cyan]{label}[/] [dim]same server as {where}, findings shown there[/]"]
    if not server.entry.findings:
        return [f"    [cyan]{label}[/] [dim]no finding[/]"]
    return [f"    [cyan]{label}[/]", *(_finding_line(f) for f in server.entry.findings)]


def _config_lines(config: ConfigResult, by_id: dict[str, ScannedServer]) -> list[str]:
    section = f" [{escape(printable(config.section, 120))}]" if config.section else ""
    verified = "" if config.location.verified else " [dim](path not verified)[/]"
    head = f"  {escape(printable(shown_path(config.location.path), 200))}{section}{verified}"
    if config.status == "error":
        return [head, f"    [yellow]not read: {escape(printable(config.error or '', 300))}[/]"]
    if config.status == "no-servers":
        return [head, "    [dim]no MCP server configured[/]"]
    return [head, *(line for name, sid in config.servers
                     for line in _server_lines(name, by_id[sid], config))]


def render_scan(result: ScanResult) -> None:
    by_id = {s.id: s for s in result.servers}
    if not result.configs:
        console.print(f"No MCP client configuration found in the {len(result.searched)} "
                      "known locations.")
        return
    for client in CLIENTS:
        configs = [c for c in result.configs if c.location.client == client]
        if configs:
            console.print(f"\n[bold]{client}[/]")
            for config in configs:
                console.print("\n".join(_config_lines(config, by_id)), highlight=False)
    _summary(result)


def _count(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def _summary(result: ScanResult) -> None:
    files = len({c.location.path for c in result.configs})
    places = sum(len(s.locations) for s in result.servers)
    findings = sum(len(s.entry.findings) for s in result.servers)
    line = (f"\n{_count(files, 'config file')}, {_count(places, 'server entry', 'server entries')}"
            f", {_count(len(result.servers), 'distinct server')}, "
            f"{_count(findings, 'finding')}")
    highest = result.highest
    if findings and highest is not None:
        line += f", highest risk [{RISK_STYLES[highest]}]{highest.name}[/]"
    console.print(line + ". Static check of the configs only: no server was started.")


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def _occurrence(o: Occurrence) -> dict[str, Any]:
    return {"client": o.client, "path": str(o.path), "section": o.section, "name": o.name}


def _config(c: ConfigResult) -> dict[str, Any]:
    return {"client": c.location.client, "path": str(c.location.path),
            "scope": c.location.scope, "path_verified": c.location.verified,
            "section": c.section, "status": c.status, "error": c.error,
            "servers": [{"name": name, "server": sid} for name, sid in c.servers]}


def _server(s: ScannedServer) -> dict[str, Any]:
    return {"id": s.id, "name": s.entry.name, "risk": s.risk.name,
            "locations": [_occurrence(o) for o in s.locations],
            "findings": [{"id": f.id, "category": f.category, "risk": f.risk.name,
                          "evidence": f.evidence} for f in s.entry.findings]}


def scan_to_json(result: ScanResult) -> str:
    """`configs` lists each file read, by client; each server, audited once,
    is in `servers` with every place it was found."""
    highest = result.highest
    payload = {
        "tool": {"name": "mcp-guard", "version": __version__},
        "searched": len(result.searched),
        "configs": [_config(c) for c in result.configs],
        "servers": [_server(s) for s in result.servers],
        "summary": {
            "configs": len({c.location.path for c in result.configs}),
            "unreadable": sum(1 for c in result.configs if c.status == "error"),
            "server_entries": sum(len(s.locations) for s in result.servers),
            "distinct_servers": len(result.servers),
            "findings": sum(len(s.entry.findings) for s in result.servers),
            "highest_risk": highest.name if highest is not None else None,
        },
    }
    return json.dumps(payload, indent=2)


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #


def _text(path: Path, cache: dict[Path, str]) -> str:
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            cache[path] = ""
    return cache[path]


_PROJECT = "project "


def _line(o: Occurrence, cache: dict[Path, str]) -> int:
    """The server's line; in ~/.claude.json, searched from its project's key,
    since the same name often appears under several projects."""
    text = _text(o.path, cache)
    after = 0
    if o.section and o.section.startswith(_PROJECT):
        key = json.dumps(o.section[len(_PROJECT):])
        found = re.search(re.escape(key) + r"\s*:", text)
        after = found.start() if found else 0
    return locate(text, o.name, after)


def _location(o: Occurrence, cache: dict[Path, str]) -> dict[str, Any]:
    return {"physicalLocation": {
        "artifactLocation": {"uri": o.path.as_uri()},
        "region": {"startLine": _line(o, cache)}}}


def _results(server: ScannedServer, cache: dict[Path, str]) -> list[dict[str, Any]]:
    first, others = server.locations[0], server.locations[1:]
    results = []
    for finding in server.entry.findings:
        result = finding_result(server.entry, finding, first.path.as_uri(), _line(first, cache))
        result["message"]["text"] = f"{first.client}: {result['message']['text']}"
        if others:
            result["relatedLocations"] = [
                {"id": index, "message": {"text": f"same server: {_where(o)}"},
                 **_location(o, cache)}
                for index, o in enumerate(others)]
        results.append(result)
    return results


def scan_to_sarif(result: ScanResult, ruleset: RuleSet) -> dict[str, Any]:
    """One run, one result per finding of each distinct server, located in
    the config where the server was first found; the other places are
    `relatedLocations`. Paths are absolute `file://` URIs: the configs
    live outside any repository."""
    cache: dict[Path, str] = {}
    entries = tuple(s.entry for s in result.servers)
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "mcp-guard", "version": __version__,
                            "informationUri": INFORMATION_URI,
                            "rules": rule_descriptors(ruleset, entries)}},
        "results": [r for s in result.servers for r in _results(s, cache)],
    }]}

