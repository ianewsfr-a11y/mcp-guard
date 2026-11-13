# Detection benchmark

A synthetic corpus with ground truth, run through the real audit pipeline. It measures tool poisoning, the three capability tags, the `agent-exfiltration-surface` rule (`--combined`) and the poisoning detector applied to tool-result texts. Its goal is to turn detector changes into measured, reviewed changes.

| File | Role |
|---|---|
| `corpus.py` | Tools, sets and tool results, with their ground truth. Everything is made up. Attacker hosts are under `.invalid` |
| `bench.py` | Runs the corpus through `pipeline.run_audit` with live captures injected (the `inspect --live --combined` path, without the transport) and computes TP, FP, FN, TN, precision and recall |
| `baseline.json` | The outcomes and metrics of the current release, case by case |
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

## Known limits

- The corpus is small and was written by the people who write the detectors. Its rates describe this corpus, not MCP servers at large.
- The tool-result measure applies the static poisoning detector to result texts. The proxy does not read tool results yet, so this is the reference point for that future work, not a claim about the proxy.
