"""mcp-guard: minimalist security audit CLI for MCP servers and AI agents."""

__version__ = "0.13.1"

from .analysis import analyze_server, analyze_tool
from .analyzer import analyze, audit
from .collector import collect
from .formats import discover, load_config, strip_jsonc
from .models import AuditEntry, ConfigFormatError, Finding, Risk
from .rules import DEFAULT_RULESET, RuleSet, load_ruleset, tokenize
from .snapshot import MCPSnapshot

__all__ = [
    "DEFAULT_RULESET",
    "AuditEntry",
    "ConfigFormatError",
    "Finding",
    "MCPSnapshot",
    "Risk",
    "RuleSet",
    "__version__",
    "analyze",
    "analyze_server",
    "analyze_tool",
    "audit",
    "collect",
    "discover",
    "load_config",
    "load_ruleset",
    "strip_jsonc",
    "tokenize",
]
