"""Schema patterns come from the server and must not stall the scan.

Python's `re` backtracks: before this fix, "^(.|.|.)*Z$" (11 characters),
declared as the `pattern` of any string parameter, kept `inspect --combined`
busy for minutes. Patterns are now only run when they belong to a subset
whose cost is bounded; any other pattern is "not judged", hence unbounded.

The hostile patterns run in a child process with a timeout, so a regression
fails this test instead of hanging the suite.
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from mcp_guard.capability_schema import MAX_QUANTIFIERS, permissive_pattern, safe_to_run

ROOT = Path(__file__).resolve().parents[1]
HOSTILE = ["^(.|.|.)*Z$", "^(.|.|.|.)*Z$", "^" + ".*" * 14 + "Z$", "(a+)+$", "^(\\w+\\s?)*$",
           "((((x*)*)*)*)*y", "^(?:a|a?)+$"]


@pytest.mark.unit
@pytest.mark.parametrize("pattern, safe", [
    ("^[a-z0-9_-]+\\.yaml$", True),
    ("a{2,5}b", True),
    ("^[]a]+$", True),            # a leading "]" is a literal in a class
    ("^[*+?(]+$", True),          # quantifier characters inside a class are literals
    ("^\\(x\\)*$", True),         # an escaped parenthesis is not a group
    ("^.*.*.*$", True),           # MAX_QUANTIFIERS adjacent quantifiers
    ("^.*.*.*.*$", False),        # one more
    ("^(.|.|.)*Z$", False),       # quantified group
    ("^(?:[a-z]+/)*x$", False),   # quantified non-capturing group
    ("(a){3}", False),            # counted repetition of a group
    ("(a)\\1", False),            # backreference
    ("(?P<x>a)(?P=x)", False),    # named backreference
    ("(?=x)y", False),            # lookahead
    ("(?<!x)y", False),           # lookbehind
    ("[a-z", False),              # unbalanced class
])
def test_only_bounded_patterns_are_run(pattern, safe):
    assert safe_to_run(pattern) is safe
    if not safe:
        assert permissive_pattern(pattern) is True  # not judged: not a bound


@pytest.mark.unit
def test_the_quantifier_budget_is_small():
    assert MAX_QUANTIFIERS == 3


def _in_child(code: str, timeout: float = 30) -> str:
    proc = subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=ROOT,
                          capture_output=True, text=True, timeout=timeout, check=False)
    assert proc.returncode == 0, proc.stderr[-500:]
    return proc.stdout


@pytest.mark.unit
def test_hostile_patterns_return_at_once():
    out = _in_child(f"""
        import json, time
        from mcp_guard.capability_schema import permissive_pattern
        started = time.perf_counter()
        results = [permissive_pattern(p) for p in {HOSTILE!r}]
        print(json.dumps([results, time.perf_counter() - started]))
    """)
    results, seconds = json.loads(out)
    assert all(results) and seconds < 2


@pytest.mark.unit
def test_a_hostile_pattern_on_any_parameter_does_not_stall_tagging():
    out = _in_child(f"""
        import json, time
        from mcp_guard.capabilities import tag_tool
        from mcp_guard.snapshot import Provenance, ToolSnapshot
        props = {{f"p{{i}}": {{"type": "string", "pattern": p}}
                 for i, p in enumerate({HOSTILE!r})}}
        props["config_path"] = {{"type": "string", "pattern": "^(.|.|.)*Z$"}}
        tool = ToolSnapshot(name="t", description="Read the file at path and return it.",
                            input_schema={{"type": "object", "properties": props}},
                            provenance=Provenance(origin="live", path="tools/list[0]"))
        started = time.perf_counter()
        tagged = tag_tool(tool)
        print(json.dumps([sorted(tagged.capabilities), time.perf_counter() - started]))
    """)
    capabilities, seconds = json.loads(out)
    assert "reads_private" in capabilities and seconds < 2
