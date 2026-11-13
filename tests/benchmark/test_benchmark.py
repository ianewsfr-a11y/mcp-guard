"""The detection benchmark: outcomes must match `baseline.json` exactly.

A failure lists the cases whose outcome changed. A regression must be fixed;
an improvement is recorded on purpose with
`python tests/benchmark/bench.py --update-baseline`, so the diff of
`baseline.json` shows it in review.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import bench
import corpus
import pytest

from mcp_guard.capabilities import CAPABILITIES

HERE = Path(__file__).resolve().parent
SERVER = HERE.parent / "fixtures" / "bench_server.py"


def _changes(baseline: dict, current: dict) -> list[str]:
    lines = []
    for group, cases in current["cases"].items():
        before = {json.dumps({k: v for k, v in c.items() if k not in ("outcome",)},
                             sort_keys=True): c["outcome"] for c in baseline["cases"][group]}
        for case in cases:
            key = json.dumps({k: v for k, v in case.items() if k not in ("outcome",)},
                             sort_keys=True)
            if before.get(key) != case["outcome"]:
                name = case.get("id") or case.get("set")
                lines.append(f"{group} {name} {case.get('capability', '')}: "
                             f"{before.get(key, 'new or changed case')} -> {case['outcome']}")
    return lines


@pytest.fixture(scope="module")
def report():
    return bench.measure()


@pytest.mark.unit
def test_outcomes_match_the_baseline(report):
    baseline = json.loads(bench.BASELINE.read_text(encoding="utf-8"))
    changes = _changes(baseline, report)
    assert not changes and report["metrics"] == baseline["metrics"], (
        "benchmark outcomes changed (update the baseline only for an intended improvement):\n"
        + "\n".join(changes or ["metrics differ"]))


@pytest.mark.unit
def test_a_changed_outcome_is_reported(report):
    """The comparison itself: one flipped case must be named."""
    altered = json.loads(json.dumps(report))
    case = altered["cases"]["poisoning"][0]
    case["outcome"] = "fn" if case["outcome"] == "tp" else "tp"
    changes = _changes(altered, report)
    assert len(changes) == 1 and changes[0].startswith(f"poisoning {case['id']}")


@pytest.mark.unit
def test_corpus_is_well_formed():
    ids = [t["id"] for t in corpus.TOOLS] + [r["id"] for r in corpus.RESULTS]
    assert len(ids) == len(set(ids))
    for tool in corpus.TOOLS:
        assert tool["sets"] and set(tool["sets"]) <= set(corpus.SETS), tool["id"]
        assert set(tool["caps"]) <= set(CAPABILITIES), tool["id"]
    for name in corpus.SETS:
        assert bench.set_tools(corpus.TOOLS, name), name
    names = {}
    for tool in corpus.TOOLS:  # a tool name is unique within each server of a set
        for set_name in tool["sets"]:
            key = (set_name, bench.server_of(tool, set_name), tool["name"])
            assert key not in names, key
            names[key] = tool["id"]


@pytest.mark.unit
def test_corpus_is_synthetic_only():
    """The public corpus stays made up: only its fictional servers, and every
    host or address under .invalid."""
    assert {t["server"] for t in corpus.TOOLS} <= {None, "feedhub", "files", "workspace"}
    text = json.dumps([corpus.TOOLS, corpus.SETS, corpus.RESULTS], ensure_ascii=False).lower()
    hosts = set(re.findall(r"https?://([a-z0-9.-]+)", text)) | set(
        re.findall(r"@([a-z0-9-]+\.[a-z.]+)", text))
    assert all(h.endswith(".invalid") for h in hosts), hosts


@pytest.mark.unit
def test_every_measure_has_both_classes(report):
    """A measure without positives or negatives would hide regressions."""
    for name in ("poisoning", "combined", "results_static_detector"):
        m = report["metrics"][name]
        assert m["tp"] + m["fn"] > 0 and m["fp"] + m["tn"] > 0, name
    for capability, m in report["metrics"]["capabilities"].items():
        assert m["tp"] + m["fn"] > 0 and m["fp"] + m["tn"] > 0, capability


@pytest.mark.unit
def test_summary_lists_every_measure(report):
    table = bench.summary(report)
    assert table.count("\n") == 2 + 1 + len(CAPABILITIES) + 2 - 1


def _live(set_name: str, tmp_path: Path) -> list:
    servers = sorted({bench.server_of(t, set_name) for t in bench.set_tools(corpus.TOOLS,
                                                                              set_name)})
    config = tmp_path / f"{set_name}.json"
    config.write_text(json.dumps({"mcpServers": {
        name: {"command": sys.executable, "args": [str(SERVER), set_name, name]}
        for name in servers}}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_guard", "inspect", str(config), "--live", "--yes",
         "--combined", "--format", "json"], check=False, capture_output=True, text=True,
        timeout=120)
    return json.loads(proc.stdout[proc.stdout.index("["):])


@pytest.mark.integration
@pytest.mark.parametrize("set_name", ["aggregator_fs", "fp_trap"])
def test_in_process_audit_matches_inspect_live(set_name, tmp_path):
    """The benchmark skips the transport; the findings must be the same."""
    live = _live(set_name, tmp_path)
    run = bench.audit_set(corpus.TOOLS, set_name)
    expected = sorted((e.kind, e.server, e.name, e.risk.name,
                       tuple(sorted(f.category for f in e.findings)))
                      for e in run.entries if e.kind == "tool")
    seen = sorted((e["kind"], e["server"], e["name"], e["risk"],
                   tuple(sorted(f["category"] for f in e["findings"])))
                  for e in live if e["kind"] == "tool")
    assert seen == expected
    combined = next(e["combined"] for e in live if e.get("combined"))
    assert combined["status"] == run.combined.status
