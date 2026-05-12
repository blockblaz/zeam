# scripts/devnet-profile/

Thin shell+awk tooling for capturing a system-level profile of a running
zeam node in a multi-node devnet.

## Contents

| File | Purpose |
|---|---|
| `capture.sh` | Attach `perf` (or `samply`) to a running zeam process, record for N seconds, generate flamegraph |
| `parse-slot-probes.awk` | Convert `slot_probe over budget` lines from a zeam log to a 5-column TSV |
| `test/sample-log.txt` | Synthetic input for testing the awk parser |
| `test/expected-slot-probe.tsv` | Expected output (used by `diff` in tests) |

## Quick usage

```bash
# 1. Start lean-quickstart devnet manually (see docs/perf/devnet/README.md)

# 2. Capture 30 min of zeam_0
scripts/devnet-profile/capture.sh "zeam.*zeam_0" 1800 \
    docs/perf/devnet/raw/$(date +%F)/

# 3. Extract slot probes
grep "slot_probe over budget" \
    lean-quickstart/local-devnet/data/zeam_0/stderr.log \
  | awk -f scripts/devnet-profile/parse-slot-probes.awk \
  > docs/perf/devnet/baselines/$(date +%F)-slot_probe.tsv
```

Full runbook + summary template: **`docs/perf/devnet/README.md`**.

## Testing the awk parser locally

```bash
awk -f scripts/devnet-profile/parse-slot-probes.awk \
    < scripts/devnet-profile/test/sample-log.txt \
    | diff scripts/devnet-profile/test/expected-slot-probe.tsv -
```

Expected: no output (clean diff).
