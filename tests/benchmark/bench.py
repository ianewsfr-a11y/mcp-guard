"""Detection benchmark: run the corpora through the real audit pipeline and
measure true/false positives, precision, recall and timings.

Two corpora, reported apart:

- `corpus.py` (historical): the Lot 0 corpus, against which detectors are tuned;
- `holdout.py`: cases written before the capability rules, never tuned for,
  including the official reference servers. It measures generalization.

The audit is `pipeline.run_audit` with live captures injected: the same path
as `inspect --live --combined`, minus the transport (`test_benchmark.py`
checks that both agree). No network, no subprocess.

A capability counts as detected when the combined rule's surface carries it
(medium or high confidence). Low-confidence tags are "uncertain": reported
with each case, never counted as detections.

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
from types import ModuleType
from typing import Any

from mcp_guard.capabilities import CAPABILITIES
from mcp_guard.pipeline import AuditRun, run_audit
from mcp_guard.poisoning import signals
from mcp_guard.rules import DEFAULT_RULESET

HERE = Path(__file__).resolve().parent
BASELINE = HERE / "baseline.json"
FROZEN_BASELINE = HERE / "baseline-0.13.1.json"  # Lot 0 reference, never rewritten
POISON_CATEGORIES = ("tool-poisoning",)
CORPORA = ("historical", "holdout")


def load(name: str) -> ModuleType:
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    return __import__({"historical": "corpus", "holdout": "holdout"}[name])


def raw_tool(tool: dict[str, Any]) -> dict[str, Any]:
    if "raw" in tool:
        return tool["raw"]
    properties = {name: {"type": "string", "description": desc}
                  for name, desc in tool["params"].items()}
    return {"name": tool["name"], "description": tool["description"],
            "inputSchema": {"type": "object", "properties": properties}}


def truth(tool: dict[str, Any], capability: str) -> str:
    """`yes`, `no` or `ambiguous`."""
    if "truth" in tool:
        return str(tool["truth"][capability])
    return "yes" if capability in tool["caps"] else "no"


def server_of(tool: dict[str, Any], set_name: str) -> str:
    return tool.get("server") or f"bench-{set_name}"


def set_tools(tools: list[dict[str, Any]], set_name: str) -> list[dict[str, Any]]:
    return [t for t in tools if set_name in t["sets"]]


def audit_set(tools: list[dict[str, Any]], set_name: str) -> AuditRun:
    """One config per set: one server per `server` value, each live-captured."""
    servers: dict[str, list[dict[str, Any]]] = {}
    for tool in set_tools(tools, set_name):
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
    """Every tool with a `poisoned` truth, judged in the first set it belongs to."""
    cases = []
    for tool in (t for t in tools if "poisoned" in t):
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


def _caps_by_tool(run: AuditRun, uncertain: bool) -> dict[tuple[str, str], set[str]]:
    tags: dict[tuple[str, str], set[str]] = {}
    combined = run.combined
    if combined is None:
        return tags
    if uncertain:
        for tool in getattr(combined, "uncertain", ()):
            tags.setdefault((tool.server or "", tool.name), set()).update(
                t.capability for t in tool.uncertain)
        return tags
    for capability, tagged in combined.surface.items():
        for tool in tagged:
            tags.setdefault((tool.server or "", tool.name), set()).add(capability)
    return tags


def _capability_case(tool: dict[str, Any], capability: str, found: set[str],
                     doubtful: set[str]) -> dict[str, Any]:
    expected, detected = truth(tool, capability), capability in found
    if expected == "ambiguous":
        outcome = ("ambiguous-asserted" if detected else
                   "ambiguous-uncertain" if capability in doubtful else "ambiguous-untagged")
    else:
        outcome = _outcome(expected == "yes", detected)
    return {"id": tool["id"], "capability": capability, "expected": expected,
            "detected": detected, "uncertain": capability in doubtful, "outcome": outcome}


def capability_cases(tools: list[dict[str, Any]], sets: dict[str, dict[str, Any]],
                     runs: dict[str, AuditRun]) -> list[dict[str, Any]]:
    """Each (tool, capability) once, judged in the first set (in `sets` order)
    that holds the tool, with its server context there. Poisoning cases of the
    historical corpus outside the combined sets have no capability truth."""
    cases, seen = [], set()
    for set_name, set_truth in sets.items():
        found = _caps_by_tool(runs[set_name], uncertain=False)
        doubtful = _caps_by_tool(runs[set_name], uncertain=True)
        for tool in set_tools(tools, set_name):
            if tool["id"] in seen or ("poisoned" in tool and set_truth["expected_alert"] is None):
                continue
            seen.add(tool["id"])
            key = (server_of(tool, set_name), tool["name"])
            cases += [_capability_case(tool, c, found.get(key, set()), doubtful.get(key, set()))
                      for c in CAPABILITIES]
    return cases


def combined_cases(sets: dict[str, dict[str, Any]],
                   runs: dict[str, AuditRun]) -> list[dict[str, Any]]:
    cases = []
    for set_name, set_truth in sets.items():
        if set_truth["expected_alert"] is None:
            continue
        combined = runs[set_name].combined
        status = combined.status if combined else "missing"
        alert = status in ("triggered", "partial")
        cases.append({"set": set_name, "expected": set_truth["expected_alert"],
                      "status": status, "reason": combined.reason if combined else "",
                      "outcome": _outcome(set_truth["expected_alert"], alert)})
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


def _ambiguous(cases: list[dict[str, Any]]) -> dict[str, int]:
    return {k: sum(c["outcome"] == f"ambiguous-{k}" for c in cases)
            for k in ("asserted", "uncertain", "untagged")}


def measure_corpus(name: str) -> dict[str, Any]:
    module = load(name)
    tools, sets, results = module.TOOLS, module.SETS, module.RESULTS
    runs = {set_name: audit_set(tools, set_name) for set_name in sets}
    poisoning = poisoning_cases(tools, runs)
    capabilities = capability_cases(tools, sets, runs)
    combined = combined_cases(sets, runs)
    in_results = result_cases(results, tools)
    metrics: dict[str, Any] = {
        "capabilities": {c: _tally([x for x in capabilities if x["capability"] == c])
                         for c in CAPABILITIES},
        "capabilities_ambiguous": _ambiguous(capabilities),
        "capabilities_uncertain_flags": sum(c["uncertain"] for c in capabilities),
        "combined": _tally(combined),
    }
    if poisoning:
        metrics["poisoning"] = _tally(poisoning)
    if in_results:
        metrics["results_static_detector"] = _tally(in_results)
    return {"corpus": {"tools": len(tools), "sets": len(sets), "results": len(results)},
            "metrics": metrics,
            "cases": {"poisoning": poisoning, "capabilities": capabilities,
                      "combined": combined, "results": in_results}}


def measure() -> dict[str, Any]:
    return {name: measure_corpus(name) for name in CORPORA}


def timings(repeat: int) -> dict[str, Any]:
    """Median and max wall time per stage, in milliseconds (informative only)."""
    historical = load("historical")

    def clock(work: Callable[[], object]) -> dict[str, float]:
        samples = []
        for _ in range(repeat):
            started = time.perf_counter()
            work()
            samples.append((time.perf_counter() - started) * 1000)
        return {"median_ms": round(statistics.median(samples), 2),
                "max_ms": round(max(samples), 2)}

    return {"repeat": repeat,
            "historical_measure": clock(lambda: measure_corpus("historical")),
            "holdout_measure": clock(lambda: measure_corpus("holdout")),
            "audit_largest_set": clock(lambda: audit_set(historical.TOOLS, "aggregator_fs")),
            "results_detector": clock(lambda: result_cases(historical.RESULTS,
                                                           historical.TOOLS))}


def _rows(name: str, report: dict[str, Any]) -> list[str]:
    metrics = report["metrics"]
    named = [*((f"capability {c}", v) for c, v in metrics["capabilities"].items()),
             ("combined rule", metrics["combined"])]
    if "poisoning" in metrics:
        named.insert(0, ("tool poisoning", metrics["poisoning"]))
    if "results_static_detector" in metrics:
        named.append(("tool results (static detector)", metrics["results_static_detector"]))
    return [f"| {name} | {label} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | "
            f"{m['precision']} | {m['recall']} |" for label, m in named]


def summary(report: dict[str, Any]) -> str:
    rows = ["| Corpus | Measure | TP | FP | FN | TN | Precision | Recall |",
            "|---|---|---|---|---|---|---|---|"]
    for name in CORPORA:
        rows += _rows(name, report[name])
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
        print(json.dumps({n: report[n]["metrics"] for n in CORPORA}, indent=2))


if __name__ == "__main__":
    main()
