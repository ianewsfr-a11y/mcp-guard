"""SARIF 2.1.0 output, shaped for GitHub code scanning."""

from __future__ import annotations

import json
import re
from typing import Any

from . import __version__
from .combined import RULE as COMBINED_RULE
from .combined import CombinedResult
from .models import AuditEntry, Finding, Risk
from .rules import BUILTIN_CHECKS, RuleSet

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/ianewsfr-a11y/mcp-guard"

_LEVEL = {Risk.LOW: "note", Risk.MEDIUM: "warning", Risk.HIGH: "error",
          Risk.CRITICAL: "error"}
# GitHub bands: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY = {Risk.LOW: "2.0", Risk.MEDIUM: "5.5", Risk.HIGH: "8.0",
                      Risk.CRITICAL: "9.5"}
_BUILTIN_RISK = {"tool-poisoning": Risk.CRITICAL, "hardcoded-secret": Risk.HIGH,
                 "annotation-contradiction": Risk.HIGH,
                 "broad-filesystem-scope": Risk.HIGH, "tool-changed": Risk.HIGH,
                 "server-changed": Risk.HIGH, "tool-removed": Risk.LOW,
                 "server-removed": Risk.LOW}


def rule_id(category: str) -> str:
    return f"mcp-guard/{category}"


def _default_risks(ruleset: RuleSet) -> dict[str, Risk]:
    risks = {c: _BUILTIN_RISK.get(c, Risk.MEDIUM) for c in BUILTIN_CHECKS}
    for rule in ruleset.rules:
        risks[rule.category] = max(rule.risk, risks.get(rule.category, Risk.LOW))
    return risks


def _rules(ruleset: RuleSet, entries: tuple[AuditEntry, ...]) -> list[dict[str, Any]]:
    risks = _default_risks(ruleset)
    for finding in (f for e in entries for f in e.findings):
        risks[finding.category] = max(finding.risk, risks.get(finding.category, Risk.LOW))
    descriptors = []
    for category in sorted(risks):
        description = ruleset.describe(category)
        descriptors.append({
            "id": rule_id(category),
            "name": "".join(part.capitalize() for part in category.split("-")),
            "shortDescription": {"text": description},
            "fullDescription": {"text": description},
            "help": {"text": f"{description} Review whether the agent needs this "
                             f"capability, and restrict or sandbox it if not."},
            "defaultConfiguration": {"level": _LEVEL[risks[category]]},
            "properties": {"tags": ["security", "mcp"], "precision": "medium",
                           "security-severity": _SECURITY_SEVERITY[risks[category]]},
        })
    return descriptors


_DUPLICATE_SUFFIX = re.compile(r"^(?P<base>.+) #(?P<n>\d+)$")


def _patterns(name: str) -> list[re.Pattern[str]]:
    in_json = re.escape(json.dumps(name)[1:-1])  # as escaped inside a JSON string
    plain = re.escape(name)
    return [re.compile(p, re.MULTILINE) for p in (
        rf'"name"\s*:\s*"{in_json}"',               # JSON tool, Continue entry
        rf'"{in_json}"\s*:\s*\{{',                  # JSON server key -> object
        rf"^\s*-\s*name:\s*['\"]?{plain}['\"]?\s*$",  # YAML list item
        rf"^\s*['\"]?{plain}['\"]?\s*:\s*$",        # YAML mapping key
    )]


def _starts(text: str, name: str) -> list[int]:
    return sorted({hit.start() for p in _patterns(name) for hit in p.finditer(text)})


def locate(text: str, name: str) -> int:
    """1-based line where `name` is declared, or 1 if not found. A
    de-duplicated name such as `Remote #2` maps to the 2nd declaration."""
    starts, occurrence = _starts(text, name), 1
    duplicate = _DUPLICATE_SUFFIX.match(name)
    if not starts and duplicate:
        starts, occurrence = _starts(text, duplicate["base"]), int(duplicate["n"])
    if len(starts) < occurrence:
        return 1
    return text.count("\n", 0, starts[occurrence - 1]) + 1


def _result(entry: AuditEntry, finding: Finding, uri: str, line: int) -> dict[str, Any]:
    rid = rule_id(finding.category)
    return {
        "ruleId": rid,
        "level": _LEVEL[finding.risk],
        "message": {"text": f"{entry.kind} '{entry.label}': {finding.category} "
                            f"[{finding.risk.name}] ({finding.evidence})"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line},
        }}],
        # the finding's stable id: same value as in the JSON report
        "partialFingerprints": {"mcpGuardFinding/v1": finding.id},
    }


_SERVER_KEYS = ("mcpServers", "servers", "context_servers")


def _servers_line(text: str) -> int:
    """Line of the key that holds the servers, for a config-level finding."""
    for key in _SERVER_KEYS:
        if _starts(text, key):
            return locate(text, key)
    return 1


def _config_result(entry: AuditEntry, finding: Finding, uri: str, text: str,
                   combined: CombinedResult | None) -> dict[str, Any]:
    result = _result(entry, finding, uri, _servers_line(text))
    servers = list(combined.servers) if combined else []
    if servers:
        result["relatedLocations"] = [
            {"id": index, "message": {"text": f"server '{name}'"},
             "physicalLocation": {"artifactLocation": {"uri": uri},
                                  "region": {"startLine": locate(text, name)}}}
            for index, name in enumerate(servers)]
    return result


def _notifications(combined: CombinedResult | None) -> list[dict[str, Any]]:
    if combined is None or combined.status not in ("not-evaluated", "partial"):
        return []
    return [{"level": "note",
             "message": {"text": f"{COMBINED_RULE} {combined.status}: {combined.reason}"}}]


def to_sarif(entries: tuple[AuditEntry, ...], ruleset: RuleSet, uri: str,
             text: str, combined: CombinedResult | None = None) -> dict[str, Any]:
    """Without `combined` (and without config entries), the report is exactly
    that of v0.6."""
    results = [
        _config_result(entry, finding, uri, text, combined) if entry.kind == "config"
        else _result(entry, finding, uri, locate(text, entry.server or entry.name))
        for entry in entries for finding in entry.findings
    ]
    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": "mcp-guard",
            "version": __version__,
            "informationUri": INFORMATION_URI,
            "rules": _rules(ruleset, entries),
        }},
        "results": results,
    }
    notifications = _notifications(combined)
    if notifications:
        run["invocations"] = [{"executionSuccessful": True,
                               "toolExecutionNotifications": notifications}]
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
