"""The detection benchmark: outcomes must match `baseline.json` exactly.

A failure lists the cases whose outcome changed. A regression must be fixed;
an improvement is recorded on purpose with
`python tests/benchmark/bench.py --update-baseline`, so the diff of
`baseline.json` shows it in review. `baseline-0.13.1.json` is the Lot 0
reference and is never rewritten.
"""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import bench
import pytest

from mcp_guard.capabilities import CAPABILITIES

HERE = Path(__file__).resolve().parent
SERVER = HERE.parent / "fixtures" / "bench_server.py"
FROZEN_SHA256 = "68df2840704bb1c5cc78c4a5042ab3e8788ebddef02d5abe613a0fddc1cb1cff"
FROZEN_LOT2_SHA256 = "a5ae1958509bc77c2d84f9874467602d781cee81ed6bc38e27f291cad0c271ee"


def _key(case: dict) -> str:
    return json.dumps({k: v for k, v in case.items()
                       if k not in ("outcome", "detected", "uncertain", "risk", "categories",
                                    "status", "reason", "signals", "partial",
                                    "relevant")}, sort_keys=True)


def _changes(baseline: dict, current: dict) -> list[str]:
    lines = []
    for corpus_name in bench.REPORTS:
        for group, cases in current[corpus_name]["cases"].items():
            before = {_key(c): c["outcome"] for c in baseline[corpus_name]["cases"][group]}
            for case in cases:
                if before.get(_key(case)) != case["outcome"]:
                    name = case.get("id") or case.get("set")
                    lines.append(f"{corpus_name} {group} {name} {case.get('capability', '')}: "
                                 f"{before.get(_key(case), 'new case')} -> {case['outcome']}")
    return lines


@pytest.fixture(scope="module")
def report():
    return bench.measure()


@pytest.mark.unit
def test_outcomes_match_the_baseline(report):
    baseline = json.loads(bench.BASELINE.read_text(encoding="utf-8"))
    changes = _changes(baseline, report)
    same = all(report[n]["metrics"] == baseline[n]["metrics"] for n in bench.REPORTS)
    assert not changes and same, (
        "benchmark outcomes changed (update the baseline only for an intended improvement):\n"
        + "\n".join(changes or ["metrics differ"]))


@pytest.mark.unit
def test_the_lot0_and_lot2_references_are_frozen():
    digest = hashlib.sha256(bench.FROZEN_BASELINE.read_bytes()).hexdigest()
    assert digest == FROZEN_SHA256
    assert hashlib.sha256(bench.FROZEN_LOT2.read_bytes()).hexdigest() == FROZEN_LOT2_SHA256


@pytest.mark.unit
def test_a_changed_outcome_is_reported(report):
    altered = json.loads(json.dumps(report))
    case = altered["historical"]["cases"]["poisoning"][0]
    case["outcome"] = "fn" if case["outcome"] == "tp" else "tp"
    changes = _changes(altered, report)
    assert len(changes) == 1 and changes[0].startswith(f"historical poisoning {case['id']}")


@pytest.mark.unit
@pytest.mark.parametrize("corpus_name", bench.CORPORA)
def test_corpus_is_well_formed(corpus_name):
    module = bench.load(corpus_name)
    ids = [t["id"] for t in module.TOOLS] + [r["id"] for r in module.RESULTS]
    assert len(ids) == len(set(ids))
    for tool in module.TOOLS:
        assert tool["sets"] and set(tool["sets"]) <= set(module.SETS), tool["id"]
        for capability in CAPABILITIES:
            assert bench.truth(tool, capability) in ("yes", "no", "ambiguous"), tool["id"]
    for name in module.SETS:
        assert bench.set_tools(module.TOOLS, name), name
    names = set()
    for tool in module.TOOLS:  # a tool name is unique within each server of a set
        for set_name in tool["sets"]:
            key = (set_name, bench.server_of(tool, set_name), tool["name"])
            assert key not in names, key
            names.add(key)


@pytest.mark.unit
def test_corpus_is_synthetic_only():
    """The historical corpus stays made up: only its fictional servers, and
    every host or address under .invalid. (The holdout's official servers are
    the public reference servers already in tests/fixtures.)"""
    corpus = bench.load("historical")
    assert {t["server"] for t in corpus.TOOLS} <= {None, "feedhub", "files", "workspace"}
    text = json.dumps([corpus.TOOLS, corpus.SETS, corpus.RESULTS], ensure_ascii=False).lower()
    hosts = set(re.findall(r"https?://([a-z0-9.-]+)", text)) | set(
        re.findall(r"@([a-z0-9-]+\.[a-z.]+)", text))
    assert all(h.endswith(".invalid") for h in hosts), hosts


@pytest.mark.unit
@pytest.mark.parametrize("corpus_name", bench.CORPORA)
def test_every_measure_has_both_classes(report, corpus_name):
    """A measure without positives or negatives would hide regressions."""
    metrics = report[corpus_name]["metrics"]
    for name in ("poisoning", "combined", "results_static_detector"):
        if name in metrics:
            m = metrics[name]
            assert m["tp"] + m["fn"] > 0 and m["fp"] + m["tn"] > 0, name
    for capability, m in metrics["capabilities"].items():
        assert m["tp"] + m["fn"] > 0 and m["fp"] + m["tn"] > 0, capability


@pytest.mark.unit
def test_summary_lists_every_measure(report):
    table = bench.summary(report)
    historical = 1 + len(CAPABILITIES) + 1 + 1  # poisoning, capabilities, combined, results
    holdout = len(CAPABILITIES) + 1
    poisoning = len(report["poisoning"]["metrics"]["poisoning_by_split"])  # one row per split
    assert table.count("\n") == 1 + historical + holdout + poisoning + 1  # + coverage


def _live(set_name: str, tmp_path: Path) -> list:
    tools = bench.load("historical").TOOLS
    servers = sorted({bench.server_of(t, set_name) for t in bench.set_tools(tools, set_name)})
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
    run = bench.audit_set(bench.load("historical").TOOLS, set_name)
    expected = sorted((e.kind, e.server, e.name, e.risk.name,
                       tuple(sorted(f.category for f in e.findings)))
                      for e in run.entries if e.kind == "tool")
    seen = sorted((e["kind"], e["server"], e["name"], e["risk"],
                   tuple(sorted(f["category"] for f in e["findings"])))
                  for e in live if e["kind"] == "tool")
    assert seen == expected
    combined = next(e["combined"] for e in live if e.get("combined"))
    assert combined["status"] == run.combined.status
