"""Security rules for one server or one tool: risky capabilities, hardcoded
secrets, insecure transport, tool poisoning. Pure functions on validated
specs; `analyzer` applies them to a whole snapshot."""

from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import ValidationError

from .annotations import contradiction
from .models import AuditEntry, Finding, Risk, ServerSpec, ToolSpec, error_fields
from .poisoning import detect_poisoning
from .redact import (
    is_literal,
    is_secret_key,
    redact_args,
    redact_value,
    safe_url,
    secret_arg,
    strip_url_credentials,
)
from .rules import DEFAULT_RULESET, RuleSet

__all__ = [
    "analyze_server", "analyze_tool", "audit_server", "audit_tool", "is_secret_key",
    "malformed", "malformed_entry", "redact_args", "safe_url", "sort_entries",
    "strip_url_credentials", "with_findings",
]

_SHELL_LAUNCHERS = frozenset({"cmd", "bash", "sh", "zsh", "powershell", "pwsh"})
_DANGEROUS_FLAG = re.compile(
    r"^--(privileged|cap-add|pid=host|net=host|network=host)", re.IGNORECASE)
_BROAD_PATHS = re.compile(
    r"^(/|~|~/|[A-Za-z]:[\\/]?|/home/?|/Users/?|/etc/?|/root/?|\$HOME|%USERPROFILE%)$")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _schema_property_names(schema: dict[str, Any]) -> list[str]:
    properties = schema.get("properties")
    return list(properties) if isinstance(properties, dict) else []


def analyze_tool(tool: ToolSpec, ruleset: RuleSet = DEFAULT_RULESET,
                 server: str | None = None,
                 known_tools: frozenset[str] = frozenset()) -> AuditEntry:
    texts = (tool.description, *_schema_property_names(tool.inputSchema))
    contradicted = contradiction(tool, ruleset)
    findings = (*detect_poisoning(tool, server, known_tools),
                *ruleset.match(*texts, name=tool.name),
                *((contradicted,) if contradicted else ()))
    return AuditEntry(kind="tool", name=tool.name, server=server,
                      findings=ruleset.keep(findings))


# --------------------------------------------------------------------------- #
# Server checks
# --------------------------------------------------------------------------- #


def _secret(evidence: str) -> Finding:
    return Finding(category="hardcoded-secret", risk=Risk.HIGH, evidence=evidence)


def _secret_findings(server: ServerSpec) -> list[Finding]:
    findings = [
        _secret(f"{source} {key}={redact_value(str(value))}")
        for source, mapping in (("env", server.env), ("header", server.headers))
        for key, value in mapping.items()
        if is_secret_key(key) and is_literal(str(value))
    ]
    previous = None
    for arg in map(str, server.args):
        found = secret_arg(arg, previous)
        if found:
            findings.append(_secret(found[0]))
        previous = arg
    if server.url:
        parts = urlsplit(server.url)
        if parts.password:
            findings.append(_secret("url credentials in userinfo"))
        findings += [_secret(f"url ?{key}={redact_value(value)}")
                     for key, value in parse_qsl(parts.query)
                     if is_secret_key(key) and is_literal(value)]
    return findings


def _transport_findings(server: ServerSpec) -> list[Finding]:
    findings = []
    parts = urlsplit(server.url)
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK_HOSTS:
        findings.append(Finding(category="insecure-transport", risk=Risk.MEDIUM,
                                evidence=safe_url(server.url)))
    broad = [str(a) for a in server.args if _BROAD_PATHS.match(str(a))]
    if broad:
        findings.append(Finding(category="broad-filesystem-scope", risk=Risk.HIGH,
                                evidence=", ".join(broad)))
    flags = [str(a) for a in server.args if _DANGEROUS_FLAG.match(str(a))]
    if flags:
        findings.append(Finding(category="privileged-access", risk=Risk.CRITICAL,
                                evidence=", ".join(flags)))
    return findings


def _launch_terms(server: ServerSpec) -> list[str]:
    """Words worth matching in a launch line: the executable's basename and
    package-like args. Flags and paths are skipped (they are checked by
    dedicated rules) and a shell launcher such as `cmd /c` is not a finding
    by itself, only what it runs is."""
    executable = re.split(r"[\\/]", server.command)[-1]
    executable = re.sub(r"\.exe$", "", executable, flags=re.IGNORECASE)
    terms = [] if executable.lower() in _SHELL_LAUNCHERS else [executable]
    for arg in (part for a in server.args for part in str(a).split()):
        if arg.startswith("@"):  # scoped npm package: @scope/name@version
            arg = arg.split("/", 1)[-1]
        if arg.startswith("-") or "/" in arg or "\\" in arg:
            continue
        terms.append(re.sub(r"@[\w.^~-]+$", "", arg))
    return terms


def analyze_server(name: str, server: ServerSpec,
                   ruleset: RuleSet = DEFAULT_RULESET) -> AuditEntry:
    findings = (
        *ruleset.match(*_launch_terms(server)),
        *_secret_findings(server),
        *_transport_findings(server),
    )
    return AuditEntry(kind="server", name=name, findings=ruleset.keep(tuple(findings)))


# --------------------------------------------------------------------------- #
# Whole-config audit
# --------------------------------------------------------------------------- #


def malformed_entry(kind: Literal["server", "tool"], name: str, fields: str,
                    server: str | None = None) -> AuditEntry:
    return AuditEntry(kind=kind, name=name, server=server, findings=(Finding(
        category="malformed-entry", risk=Risk.MEDIUM,
        evidence=f"could not be parsed ({fields}), audit it manually"),))


def malformed(kind: Literal["server", "tool"], name: str,
              error: ValidationError, server: str | None = None) -> AuditEntry:
    return malformed_entry(kind, name, error_fields(error), server)


def audit_server(name: str, raw: Any, ruleset: RuleSet = DEFAULT_RULESET) -> AuditEntry:
    try:
        return analyze_server(name, ServerSpec.model_validate(raw), ruleset)
    except ValidationError as exc:
        return malformed("server", name, exc)


def audit_tool(index: int, raw: Any, ruleset: RuleSet = DEFAULT_RULESET,
               server: str | None = None) -> AuditEntry:
    fallback = raw.get("name") if isinstance(raw, dict) else None
    try:
        return analyze_tool(ToolSpec.model_validate(raw), ruleset, server)
    except ValidationError as exc:
        return malformed("tool", str(fallback or f"tools[{index}]"), exc, server)


def with_findings(entries: tuple[AuditEntry, ...],
                  extra: dict[tuple[str, str], tuple[Finding, ...]],
                  ruleset: RuleSet) -> tuple[AuditEntry, ...]:
    """Add findings to existing entries, keyed by (kind, label). Entries are
    rebuilt (not copied) so the new findings get their stable ids."""
    return tuple(
        AuditEntry(kind=e.kind, name=e.name, server=e.server,
                   findings=ruleset.keep(e.findings + extra[(e.kind, e.label)]))
        if (e.kind, e.label) in extra else e
        for e in entries
    )


def sort_entries(entries: list[AuditEntry], ruleset: RuleSet) -> tuple[AuditEntry, ...]:
    kept = [e for e in entries
            if e.name not in ruleset.ignore and e.label not in ruleset.ignore]
    return tuple(sorted(kept, key=lambda e: e.risk, reverse=True))
