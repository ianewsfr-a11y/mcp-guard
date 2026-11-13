# Detection benchmark

A synthetic corpus with ground truth, run through the real audit pipeline. It measures tool poisoning, the three capability tags, the `agent-exfiltration-surface` rule (`--combined`) and the poisoning detector applied to tool-result texts. Its goal is to turn detector changes into measured, reviewed changes.

| File | Role |
|---|---|
| `corpus.py` | Historical corpus: tools, sets and tool results, with their ground truth. Everything is made up. Attacker hosts are under `.invalid`. Detectors are tuned against it |
| `holdout.py` | Held-out corpus, written before the capability rules of v0.14 and never tuned for: synthetic cases (paths, URLs, negations, a mailbox, a news reader, private stores) and the 38 official reference tools of `tests/fixtures/official_tools.json`, annotated by what they do. Capability truth is `yes`, `no` or `ambiguous`; ambiguous cases are reported apart |
| `bench.py` | Runs the corpus through `pipeline.run_audit` with live captures injected (the `inspect --live --combined` path, without the transport) and computes TP, FP, FN, TN, precision and recall |
| `coverage_scenarios.py` | Twenty coverage scenarios for the combined rule (confirmed chains, relevant and irrelevant doubts, unreachable servers, malformed tools, misleading declarations, bounded paths, rules), with statuses written from the decision rules before the coverage model was implemented |
| `baseline.json` | The outcomes and metrics of the current code, case by case, for both corpora |
| `baseline-0.13.1.json` | The Lot 0 reference (v0.13.1, historical corpus only). Never rewritten; `test_benchmark.py` pins its SHA-256 |
| `test_benchmark.py` | Fails when any outcome differs from the baseline. It also checks that the corpus is well formed and synthetic only, and that the in-process audit agrees with a real `inspect --live` on two sets (`tests/fixtures/bench_server.py`) |

```bash
python tests/benchmark/bench.py                    # metrics as JSON
python tests/benchmark/bench.py --summary          # Markdown table
python tests/benchmark/bench.py --perf 20          # timings (informative, not asserted)
python tests/benchmark/bench.py --update-baseline  # record an intended change
```

## Changing a detector

1. Run `pytest tests/benchmark`. A failure lists every case whose outcome changed, for example `capabilities C11 sends_external: fp -> tn`.
2. **A regression** (a TP that became FN, a TN that became FP) is fixed, not recorded.
3. **An intended improvement** is recorded with `--update-baseline`, and the `baseline.json` diff goes in the same pull request.

## Adding cases

- Add cases to `corpus.py` with their ground truth. Judge what the tool does, not its words. A free path parameter reads whatever file the caller names.
- Keep both classes in every measure: `test_every_measure_has_both_classes` fails otherwise.
- Never add text taken from a private audit or a real vulnerability report. `test_corpus_is_synthetic_only` accepts only the fictional servers and `.invalid` hosts.

## Detected, uncertain, ambiguous

A capability counts as detected when the combined rule's surface carries it, that is a tag of medium or high confidence. A low-confidence tag is "uncertain": it is recorded with the case and counted apart (`capabilities_uncertain_flags`), never as a detection. For an `ambiguous` truth, the outcome is `ambiguous-asserted` (tagged anyway: an over-classification to watch), `ambiguous-uncertain` (the doubt is shown) or `ambiguous-untagged`.

## Combined verdicts

A combined case counts as an alert only when the status is `triggered`. A `partial` verdict is reported apart (`combined_partial`: on sets where an alert is justified, and on sets where it is not), since it raises no finding. The coverage scenarios are judged on their exact status and on the uncertain capability they name.

## Known limits

- The corpora are small and were written by the people who write the detectors. Their rates describe these corpora, not MCP servers at large. The held-out corpus limits, but does not remove, that bias: once a held-out failure has been looked at, fixing it turns the case into a tuned one.
- The tool-result measure applies the static poisoning detector to result texts. The proxy does not read tool results yet, so this is the reference point for that future work, not a claim about the proxy.
