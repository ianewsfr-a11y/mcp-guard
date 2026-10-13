"""Keyword rules, tokenization and custom rules files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .capabilities import CapabilityOverride
from .context import DEFAULT_EXCEPTIONS, effective_tokens
from .models import ConfigFormatError, Finding, Risk

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def tokenize(*texts: str) -> frozenset[str]:
    words: set[str] = set()
    for text in texts:
        split = _CAMEL_BOUNDARY.sub(" ", text or "").lower()
        words.update(w for w in re.split(r"[^a-z0-9]+", split) if w)
    return frozenset(words)


class Rule(BaseModel):
    """A keyword rule. `requires` adds context: the rule fires only if one of
    those tokens is also present (e.g. "update" only counts next to "sql")."""

    model_config = ConfigDict(frozen=True)

    category: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    risk: Risk
    keywords: frozenset[str]
    requires: frozenset[str] = frozenset()
    description: str = ""

    @field_validator("risk", mode="before")
    @classmethod
    def _risk(cls, value: Any) -> Risk:
        return Risk.parse(value)

    @field_validator("keywords", "requires", mode="before")
    @classmethod
    def _lowercase(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple, set, frozenset)):
            return frozenset(str(v).lower() for v in value)
        return value

    @field_validator("keywords", "requires")
    @classmethod
    def _single_words(cls, value: frozenset[str]) -> frozenset[str]:
        multi = sorted(k for k in value if tokenize(k) != {k})
        if multi:
            raise ValueError(f"keywords must be single words of letters and digits "
                             f"(names are split on `_`, `-` and case): {multi}")
        return value

    @field_validator("keywords")
    @classmethod
    def _not_empty(cls, value: frozenset[str]) -> frozenset[str]:
        if not value:
            raise ValueError("a rule needs at least one keyword")
        return value


_DB_CONTEXT = frozenset(
    {"sql", "database", "db", "table", "postgres", "postgresql", "mysql",
     "sqlite", "mongodb", "mongo", "redis", "collection"}
)

DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(category="command-execution", risk=Risk.CRITICAL,
         description="The tool or server can run arbitrary commands or code.",
         keywords=frozenset(
             {"exec", "execute", "shell", "bash", "sh", "zsh", "cmd", "powershell",
              "pwsh", "subprocess", "eval", "spawn", "popen", "terminal", "script"})),
    Rule(category="privileged-access", risk=Risk.CRITICAL,
         description="The tool or server runs with, or manages, elevated privileges.",
         keywords=frozenset(
             {"root", "sudo", "su", "runas", "admin", "administrator", "privileged",
              "setuid", "chmod", "chown"})),
    Rule(category="write-operation", risk=Risk.HIGH,
         description="The tool can create, modify or delete data.",
         keywords=frozenset(
             {"write", "delete", "remove", "rm", "unlink", "overwrite", "move",
              "rename", "mkdir", "rmdir", "truncate", "append", "create", "edit",
              "modify", "put", "patch", "push", "commit", "add", "save", "store",
              "update", "replace"})),
    Rule(category="database-write", risk=Risk.HIGH, requires=_DB_CONTEXT,
         description="The tool can modify a database.",
         keywords=frozenset({"insert", "update", "delete", "drop", "alter",
                             "truncate", "upsert"})),
    Rule(category="database", risk=Risk.MEDIUM, keywords=_DB_CONTEXT | {"query"},
         description="The tool can read from a database."),
    Rule(category="network", risk=Risk.MEDIUM,
         description="The tool can reach the network (a data exfiltration channel).",
         keywords=frozenset(
             {"http", "https", "url", "fetch", "download", "upload", "request",
              "webhook", "socket", "curl", "wget", "email", "smtp", "send", "post"})),
)

# Findings produced by dedicated checks rather than keyword rules.
BUILTIN_CHECKS: dict[str, str] = {
    "tool-poisoning": ("The tool's metadata hides instructions for the model (hidden tags, "
                       "override or concealment phrases, invisible characters)."),
    "annotation-contradiction": ("The tool claims to be read-only or non-destructive in its "
                                 "annotations, but its name or description says it writes, "
                                 "deletes or runs commands: a client may auto-approve it."),
    "hardcoded-secret": "A credential is stored in plain text in the configuration.",
    "broad-filesystem-scope": "The server is given access to a root or home directory.",
    "insecure-transport": "A remote server is reached over plain HTTP.",
    "malformed-entry": "The entry could not be parsed and must be audited manually.",
    "live-discovery-failed": "Live discovery of the server's tools failed.",
    "tool-changed": ("The tool's description or input schema differs from the lock file "
                     "(possible rug pull)."),
    "server-changed": "The server's launch command, arguments or URL differ from the lock file.",
    "tool-added": "The tool is not in the lock file.",
    "server-added": "The server is not in the lock file.",
    "tool-removed": "The tool is in the lock file but no longer present.",
    "server-removed": "The server is in the lock file but no longer present.",
}


# Listed in SARIF only when they report something, so that reports without
# such findings do not change: opt-in checks, and the poisoning of surfaces
# other than tools (resources, prompts, server instructions).
SURFACE_POISONING: dict[str, str] = {
    "resource-poisoning": ("A resource's name, title, description, URI or MIME type hides "
                           "instructions for the model."),
    "prompt-poisoning": ("A prompt's name, title, description or argument descriptions hide "
                         "instructions for the model."),
    "server-instruction-poisoning": ("The instructions the server sends at initialization "
                                     "hide instructions for the model."),
}
EXPERIMENTAL_CHECKS: dict[str, str] = {
    "agent-exfiltration-surface": (
        "Together, the active servers let an agent read private data, ingest untrusted "
        "content and send data out: a prompt injection can chain them into an "
        "exfiltration (experimental, inspect --combined)."),
}


class RuleSet(BaseModel):
    """The active rules plus names of servers/tools to leave out of the report."""

    model_config = ConfigDict(frozen=True)

    rules: tuple[Rule, ...] = DEFAULT_RULES
    ignore: frozenset[str] = frozenset()
    disabled: frozenset[str] = frozenset()
    exceptions: dict[str, frozenset[str]] = Field(
        default_factory=lambda: dict(DEFAULT_EXCEPTIONS))
    # capability tag overrides, for the --combined rule
    capabilities: tuple[CapabilityOverride, ...] = ()

    def keep(self, findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
        """Drop findings of disabled categories (incl. dedicated checks)."""
        return tuple(f for f in findings if f.category not in self.disabled)

    def vocabulary(self) -> frozenset[str]:
        return frozenset().union(*(r.keywords | r.requires for r in self.rules))

    def match(self, *texts: str, name: str = "") -> tuple[Finding, ...]:
        """Findings for texts (description, parameter names...) and a tool
        name, matched word by word with their neighbors so that contextual
        exceptions stay local."""
        tokens = effective_tokens(texts, self.exceptions, self.vocabulary(), name)
        findings = []
        for rule in self.rules:
            hits = rule.keywords & tokens
            if hits and (not rule.requires or rule.requires & tokens):
                findings.append(Finding(category=rule.category, risk=rule.risk,
                                        evidence=", ".join(sorted(hits))))
        return tuple(findings)

    def describe(self, category: str) -> str:
        for rule in self.rules:
            if rule.category == category and rule.description:
                return rule.description
        known = {**BUILTIN_CHECKS, **EXPERIMENTAL_CHECKS, **SURFACE_POISONING}
        return known.get(category, category.replace("-", " ").capitalize())


DEFAULT_RULESET = RuleSet()


class RulesFile(BaseModel):
    """Schema of a `--rules` file (YAML or JSON)."""

    model_config = ConfigDict(extra="forbid")

    extends: str = Field(default="default", pattern=r"^(default|none)$")
    disable: list[str] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)
    ignore: list[str] = Field(default_factory=list)
    exceptions: dict[str, list[str]] = Field(default_factory=dict)
    capabilities: list[CapabilityOverride] = Field(default_factory=list)

    @field_validator("exceptions")
    @classmethod
    def _exception_words(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        words = [w.lower() for k, ctx in value.items() for w in [k, *ctx]]
        multi = sorted({w for w in words if tokenize(w) != {w}})
        if multi:
            raise ValueError(f"exception keywords and contexts must be single words: {multi}")
        return {k.lower(): [c.lower() for c in ctx] for k, ctx in value.items()}

    @model_validator(mode="after")
    def _consistent(self) -> RulesFile:
        categories = [r.category for r in self.rules]
        duplicates = sorted({c for c in categories if categories.count(c) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule categories: {duplicates}")
        reserved = sorted(set(categories) & (set(BUILTIN_CHECKS) | set(EXPERIMENTAL_CHECKS)
                                             | set(SURFACE_POISONING)))
        if reserved:
            raise ValueError(f"reserved for built-in checks, pick another name: {reserved}")
        known = ({r.category for r in DEFAULT_RULES} | set(BUILTIN_CHECKS)
                 | set(EXPERIMENTAL_CHECKS) | set(SURFACE_POISONING) | set(categories))
        unknown = sorted(set(self.disable) - known)
        if unknown:
            raise ValueError(f"unknown categories in `disable`: {unknown}")
        return self

    def to_ruleset(self) -> RuleSet:
        base = DEFAULT_RULES if self.extends == "default" else ()
        overridden = {r.category for r in self.rules} | set(self.disable)
        kept = tuple(r for r in base if r.category not in overridden)
        custom = tuple(r for r in self.rules if r.category not in self.disable)
        exceptions = dict(DEFAULT_EXCEPTIONS) if self.extends == "default" else {}
        for keyword, contexts in self.exceptions.items():
            exceptions[keyword] = exceptions.get(keyword, frozenset()) | frozenset(contexts)
        return RuleSet(rules=kept + custom, ignore=frozenset(self.ignore),
                       disabled=frozenset(self.disable), exceptions=exceptions,
                       capabilities=tuple(self.capabilities))


def load_ruleset(path: Path) -> RuleSet:
    try:
        text = path.read_text(encoding="utf-8-sig")
        data = (json.loads(text) if path.suffix.lower() == ".json"
                else yaml.safe_load(text)) or {}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ConfigFormatError(f"Cannot read rules file {path}: {exc}") from exc
    try:
        return RulesFile.model_validate(data).to_ruleset()
    except ValidationError as exc:
        raise ConfigFormatError(f"Invalid rules file {path}:\n{exc}") from exc
