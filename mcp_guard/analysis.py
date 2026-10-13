"""Static analysis of servers and tools."""

from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import ValidationError

from .formats import discover
from .models import AuditEntry, Finding, Risk, ServerSpec, ToolSpec
from .poisoning import detect_poisoning
from .rules import DEFAULT_RULESET, RuleSet, tokenize

_SHELL_LAUNCHERS = frozenset({"cmd", "bash", "sh", "zsh", "powershell", "pwsh"})
_SECRET_KEY_TOKENS = frozenset(
    {"token", "key", "apikey", "secret", "password", "passwd", "pwd",
     "credential", "credentials", "auth", "authorization"}
)
# ${VAR}, ${env:VAR}, ${input:id}, ${file:/path} (VS Code, Windsurf),
# ${{ secrets.X }} (Continue), $VAR, %VAR%.
_VARIABLE_REFERENCE = re.compile(r"\$\{\{[^}]*\}\}|\$\{[^}]+\}|^\$\w+$|^%\w+%$")
_SECRET_FLAG = re.compile(
    r"^(?P<flag>--?[\w-]*(key|token|secret|password)[\w-]*)=(?P<value>.+)$", re.IGNORECASE)
_SECRET_BARE_FLAG = re.compile(r"^--?[\w-]*(key|token|secret|password)[\w-]*$",
                               re.IGNORECASE)
_NOT_A_SECRET_FLAG = re.compile(r"(file|path|dir|name|id)$", re.IGNORECASE)
_ASSIGNMENT = re.compile(r"^(?P<key>[A-Za-z_][\w.-]*)=(?P<value>.+)$")
_URL_CREDENTIALS = re.compile(r"(\w+://[^/\s:@]+:)[^@\s/]+@")
_DANGEROUS_FLAG = re.compile(
    r"^--(privileged|cap-add|pid=host|net=host|network=host)", re.IGNORECASE)
_BROAD_PATHS = re.compile(
    r"^(/|~|~/|[A-Za-z]:[\\/]?|/home/?|/Users/?|/etc/?|/root/?|\$HOME|%USERPROFILE%)$")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _schema_property_names(schema: dict[str, Any]) -> list[str]:
    properties = schema.get("properties")
    return list(properties) if isinstance(properties, dict) else []


def analyze_tool(tool: ToolSpec, ruleset: RuleSet = DEFAULT_RULESET,
                 server: str | None = None) -> AuditEntry:
    tokens = tokenize(tool.name, tool.description,
                      *_schema_property_names(tool.inputSchema))
    findings = (*detect_poisoning(tool), *ruleset.match(tokens))
    return AuditEntry(kind="tool", name=tool.name, server=server,
                      findings=ruleset.keep(findings))


# --------------------------------------------------------------------------- #
# Server checks
# --------------------------------------------------------------------------- #


def _redact(value: str) -> str:
    return f"<redacted, {len(value)} chars>"


def _is_secret_key(key: str) -> bool:
    return bool(tokenize(key) & _SECRET_KEY_TOKENS)


def _is_literal(value: str) -> bool:
    return bool(value) and not _VARIABLE_REFERENCE.search(value)


def _secret(evidence: str) -> Finding:
    return Finding(category="hardcoded-secret", risk=Risk.HIGH, evidence=evidence)


def _secret_arg(arg: str, previous: str | None) -> tuple[str, str] | None:
    """(evidence, redacted arg) when a launch argument holds a literal secret:
    `--api-key=X`, `--api-key X`, `API_KEY=X` (e.g. `docker -e`) or a URL
    with a password such as `postgres://user:pw@host/db`."""
    flag = _SECRET_FLAG.match(arg)
    if flag and _is_literal(flag["value"]) and not _NOT_A_SECRET_FLAG.search(flag["flag"]):
        return f"arg {flag['flag']}={_redact(flag['value'])}", f"{flag['flag']}=<redacted>"
    assignment = _ASSIGNMENT.match(arg)
    if (assignment and _is_secret_key(assignment["key"])
            and _is_literal(assignment["value"])):
        key = assignment["key"]
        return f"arg {key}={_redact(assignment['value'])}", f"{key}=<redacted>"
    if _URL_CREDENTIALS.search(arg):
        return "arg url credentials in userinfo", _URL_CREDENTIALS.sub(r"\1<redacted>@", arg)
    if (previous and _SECRET_BARE_FLAG.match(previous)
            and not _NOT_A_SECRET_FLAG.search(previous)
            and not arg.startswith("-") and _is_literal(arg)):
        return f"arg {previous} {_redact(arg)}", "<redacted>"
    return None


def redact_args(args: list[str]) -> list[str]:
    """Launch arguments with every literal secret replaced, for display."""
    redacted, previous = [], None
    for arg in args:
        found = _secret_arg(arg, previous)
        redacted.append(found[1] if found else arg)
        previous = arg
    return redacted


def _secret_findings(server: ServerSpec) -> list[Finding]:
    findings = [
        _secret(f"{source} {key}={_redact(str(value))}")
        for source, mapping in (("env", server.env), ("header", server.headers))
        for key, value in mapping.items()
        if _is_secret_key(key) and _is_literal(str(value))
    ]
    previous = None
    for arg in map(str, server.args):
        found = _secret_arg(arg, previous)
        if found:
            findings.append(_secret(found[0]))
        previous = arg
    if server.url:
        parts = urlsplit(server.url)
        if parts.password:
            findings.append(_secret("url credentials in userinfo"))
        findings += [_secret(f"url ?{key}={_redact(value)}")
                     for key, value in parse_qsl(parts.query)
                     if _is_secret_key(key) and _is_literal(value)]
    return findings


def safe_url(url: str) -> str:
    """Drop userinfo, query and fragment so credentials never reach the output."""
    parts = urlsplit(url)
    try:
        port = f":{parts.port}" if parts.port else ""
    except ValueError:  # non-numeric port
        port = ""
    return f"{parts.scheme}://{parts.hostname or ''}{port}{parts.path}"


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
        *ruleset.match(tokenize(*_launch_terms(server))),
        *_secret_findings(server),
        *_transport_findings(server),
    )
    return AuditEntry(kind="server", name=name, findings=ruleset.keep(tuple(findings)))


# --------------------------------------------------------------------------- #
# Whole-config audit
# --------------------------------------------------------------------------- #


def malformed(kind: Literal["server", "tool"], name: str,
              error: ValidationError, server: str | None = None) -> AuditEntry:
    fields = ", ".join(sorted({".".join(map(str, e["loc"])) or "entry"
                               for e in error.errors()}))
    return AuditEntry(kind=kind, name=name, server=server, findings=(Finding(
        category="malformed-entry", risk=Risk.MEDIUM,
        evidence=f"could not be parsed ({fields}), audit it manually"),))


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


def sort_entries(entries: list[AuditEntry], ruleset: RuleSet) -> tuple[AuditEntry, ...]:
    kept = [e for e in entries
            if e.name not in ruleset.ignore and e.label not in ruleset.ignore]
    return tuple(sorted(kept, key=lambda e: e.risk, reverse=True))


def audit(data: Any, ruleset: RuleSet = DEFAULT_RULESET) -> tuple[AuditEntry, ...]:
    found = discover(data)
    entries = [audit_server(n, s, ruleset) for n, s in found.servers.items()]
    entries += [audit_tool(i, t, ruleset) for i, t in enumerate(found.tools)]
    return sort_entries(entries, ruleset)
