"""mcp-guard: minimalist security audit CLI for MCP servers and AI agents."""

__version__ = "0.5.1"

from .analysis import analyze_server, analyze_tool, audit
from .formats import discover, load_config, strip_jsonc
from .models import AuditEntry, ConfigFormatError, Finding, Risk
from .rules import DEFAULT_RULESET, RuleSet, load_ruleset, tokenize

__all__ = [
    "DEFAULT_RULESET",
    "AuditEntry",
    "ConfigFormatError",
    "Finding",
    "Risk",
    "RuleSet",
    "__version__",
    "analyze_server",
    "analyze_tool",
    "audit",
    "discover",
    "load_config",
    "load_ruleset",
    "strip_jsonc",
    "tokenize",
]
