"""Detection benchmark: run the corpus through the real audit pipeline and
measure true/false positives, precision, recall and timings.

The audit is `pipeline.run_audit` with live captures injected: the same path
as `inspect --live --combined`, minus the transport (`test_benchmark.py`
checks that both agree). No network, no subprocess.

    python tests/benchmark/bench.py                    # print the metrics
    python tests/benchmark/bench.py --update-baseline  # rewrite baseline.json
    python tests/benchmark/bench.py --perf 20          # timings, 20 repetitions
    python tests/benchmark/bench.py --summary          # Markdown, for CI summaries
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcp_guard.capabilities import CAPABILITIES
from mcp_guard.pipeline import AuditRun, run_audit
from mcp_guard.poisoning import signals
from mcp_guard.rules import DEFAULT_RULESET

HERE = Path(__file__).resolve().parent
BASELINE = HERE / "baseline.json"
POISON_CATEGORIES = ("tool-poisoning",)


def load_corpus() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    sys.path.insert(0, str(HERE))
    import corpus

    return corpus.TOOLS, corpus.SETS, corpus.RESULTS


def raw_tool(tool: dict[str, Any]) -> dict[str, Any]:
    properties = {name: {"type": "string", "description": desc}
                  for name, desc in tool["params"].items()}
    return {"name": tool["name"], "description": tool["description"],
            "inputSchema": {"type": "object", "properties": properties}}


def server_of(tool: dict[str, Any], set_name: str) -> str:
    return tool.get("server") or f"bench-{set_name}"


def set_tools(tools: list[dict[str, Any]], set_name: str) -> list[dict[str, Any]]:
    return [t for t in tools if set_name in t["sets"]]


def audit_set(tools: list[dict[str, Any]], set_name: str) -> AuditRun:
    """One config per set: one server per `server` value, each live-captured."""
    members = set_tools(tools, set_name)
    servers: dict[str, list[dict[str, Any]]] = {}
    for tool in members:
        servers.setdefault(server_of(tool, set_name), []).append(raw_tool(tool))
    config = {"mcpServers": {name: {"command": "bench-server"} for name in servers}}
    return run_audit(config, f"bench:{set_name}", DEFAULT_RULESET, live=servers, combined=True)


def _rates(tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
    precision = round(tp / (tp + fp), 3) if tp + fp else None
    recall = round(tp / (tp + fn), 3) if tp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall}


def _outcome(expected: bool, detected: bool) -> str:
    return {(True, True): "tp", (False, True): "fp", (True, False): "fn",
            (False, False): "tn"}[(expected, detected)]


def poisoning_cases(tools: list[dict[str, Any]], runs: dict[str, AuditRun]) -> list[dict[str, Any]]:
    """Every tool once, judged in the first set it belongs to."""
    cases = []
    for tool in tools:
        run = runs[tool["sets"][0]]
        server = server_of(tool, tool["sets"][0])
        entry = next(e for e in run.entries
                     if e.kind == "tool" and e.name == tool["name"] and e.server == server)
        found = sorted({f.category for f in entry.findings})
        detected = any(c in POISON_CATEGORIES for c in found)
        cases.append({"id": tool["id"], "technique": tool["technique"],
                      "expected": tool["poisoned"], "detected": detected,
                      "outcome": _outcome(tool["poisoned"], detected), "categories": found,
                      "risk": entry.risk.name})
    return cases


def _detected_caps(run: AuditRun) -> dict[tuple[str, str], set[str]]:
    tags: dict[tuple[str, str], set[str]] = {}
    for capability, tagged in (run.combined.surface if run.combined else {}).items():
        for tool in tagged:
            tags.setdefault((tool.server or "", tool.name), set()).add(capability)
    return tags


def capability_cases(tools: list[dict[str, Any]], sets: dict[str, dict[str, Any]],
                     runs: dict[str, AuditRun]) -> list[dict[str, Any]]:
    """Each (tool, capability) of the combined-rule sets, once per tool."""
    cases, seen = [], set()
    for set_name in (s for s, v in sets.items() if v["expected_alert"] is not None):
        detected = _detected_caps(runs[set_name])
        for tool in set_tools(tools, set_name):
            if tool["id"] in seen:
                continue
            seen.add(tool["id"])
            found = detected.get((server_of(tool, set_name), tool["name"]), set())
            for capability in CAPABILITIES:
                expected = capability in tool["caps"]
                cases.append({"id": tool["id"], "capability": capability,
                              "expected": expected, "detected": capability in found,
                              "outcome": _outcome(expected, capability in found)})
    return cases


def combined_cases(sets: dict[str, dict[str, Any]],
                   runs: dict[str, AuditRun]) -> list[dict[str, Any]]:
    cases = []
    for set_name, truth in sets.items():
        if truth["expected_alert"] is None:
            continue
        combined = runs[set_name].combined
        status = combined.status if combined else "missing"
        alert = status in ("triggered", "partial")
        cases.append({"set": set_name, "expected": truth["expected_alert"], "status": status,
                      "reason": combined.reason if combined else "",
                      "outcome": _outcome(truth["expected_alert"], alert)})
    return cases


def result_cases(results: list[dict[str, Any]], tools: list[dict[str, Any]],
                 ) -> list[dict[str, Any]]:
    """Today the proxy does not read tool results: this measures what the
    static poisoning detector would say if applied to them (Lot 4 baseline)."""
    known = frozenset(t["name"] for t in tools if "aggregator" in t["sets"])
    cases = []
    for result in results:
        found = signals(result["text"], known)
        cases.append({"id": result["id"], "technique": result["technique"],
                      "expected": result["hostile"], "detected": bool(found),
                      "outcome": _outcome(result["hostile"], bool(found)),
                      "signals": sorted({s.id for s in found})})
    return cases


def _tally(cases: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {k: sum(c["outcome"] == k for c in cases) for k in ("tp", "fp", "fn", "tn")}
    return _rates(counts["tp"], counts["fp"], counts["fn"], counts["tn"])


def measure() -> dict[str, Any]:
    tools, sets, results = load_corpus()
    runs = {name: audit_set(tools, name) for name in sets}
    poisoning = poisoning_cases(tools, runs)
    capabilities = capability_cases(tools, sets, runs)
    combined = combined_cases(sets, runs)
    in_results = result_cases(results, tools)
    return {
        "corpus": {"tools": len(tools), "sets": len(sets), "results": len(results)},
        "metrics": {
            "poisoning": _tally(poisoning),
            "capabilities": {c: _tally([x for x in capabilities if x["capability"] == c])
                             for c in CAPABILITIES},
            "combined": _tally(combined),
            "results_static_detector": _tally(in_results),
        },
        "cases": {"poisoning": poisoning, "capabilities": capabilities, "combined": combined,
                  "results": in_results},
    }


def timings(repeat: int) -> dict[str, Any]:
    """Median and max wall time per stage, in milliseconds (informative only)."""
    tools, sets, results = load_corpus()

    def clock(work: Callable[[], object]) -> dict[str, float]:
        samples = []
        for _ in range(repeat):
            started = time.perf_counter()
            work()
            samples.append((time.perf_counter() - started) * 1000)
        return {"median_ms": round(statistics.median(samples), 2),
                "max_ms": round(max(samples), 2)}

    return {"repeat": repeat,
            "full_measure": clock(measure),
            "audit_all_sets": clock(lambda: [audit_set(tools, s) for s in sets]),
            "audit_largest_set": clock(lambda: audit_set(tools, "aggregator_fs")),
            "results_detector": clock(lambda: result_cases(results, tools))}


def summary(report: dict[str, Any]) -> str:
    rows = ["| Measure | TP | FP | FN | TN | Precision | Recall |", "|---|---|---|---|---|---|---|"]
    metrics = report["metrics"]
    named = [("tool poisoning", metrics["poisoning"]),
             *((f"capability {c}", v) for c, v in metrics["capabilities"].items()),
             ("combined rule", metrics["combined"]),
             ("tool results (static detector)", metrics["results_static_detector"])]
    for name, m in named:
        rows.append(f"| {name} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | "
                    f"{m['precision']} | {m['recall']} |")
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--perf", type=int, metavar="N")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    report = measure()
    if args.update_baseline:
        BASELINE.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8", newline="\n")
    if args.perf:
        print(json.dumps(timings(args.perf), indent=2))
    elif args.summary:
        print(summary(report))
    else:
        print(json.dumps(report["metrics"], indent=2))


if __name__ == "__main__":
    main()
