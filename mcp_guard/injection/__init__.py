"""Automated prompt-injection testing of an agent (`test-injection --run`)."""

from __future__ import annotations

import sys
from pathlib import Path

from .harness import PROTOCOL, ScenarioResult, ToolCall, contains_canary, judge, run_scenario
from .scenarios import ATTACKER_DOMAIN, EXPECTED_CONTACTS, Scenario, build_scenarios

__all__ = [
    "ATTACKER_DOMAIN", "EXPECTED_CONTACTS", "PROTOCOL", "Scenario", "ScenarioResult", "ToolCall",
    "agent_command", "build_scenarios", "contains_canary", "judge", "run_scenario",
]


def agent_command(target: Path) -> tuple[str, list[str]]:
    """How to start the agent: Python scripts with this interpreter, anything
    else as an executable."""
    if target.suffix.lower() == ".py":
        return sys.executable, [str(target)]
    return str(target), []
