# Devnet profile — <YYYY-MM-DD>, zeam_0 @ <commit-sha>

> Copy this file to `<date>-<short-sha>-summary.md` (e.g. `2026-05-12-43bb8362-summary.md`)
> and fill in the blanks after running `scripts/devnet-profile/capture.sh`.

**Run parameters**

- Duration: <e.g. 30 min>
- Nodes: <e.g. 4 (zeam_0..zeam_3)>
- Validators per node: <e.g. 8>
- Slot interval: 4 s (mainnet preset)
- Host: <e.g. GitHub Codespace 4-core 16GB>
- zeam build: `-Dslot-probes=true -Doptimize=ReleaseFast` at sha `<sha>`
- Sampler: <perf|samply>

## Headline numbers

- Slots observed: <count>
- Total `slot_probe over budget` events: <count>
- Worst probe (highest over-budget rate): <name> at <pct>%
- IO-thread invariant violations observed: <yes / no / count>
- Chain-worker queue max depth: <N> (block) / <N> (attestation)

## 1. Slot-budget probes

Source: `<date>-<sha>-slot_probe.tsv`.

| Probe | Events | Min | Median | p99 | Max | Budget |
|---|---:|---:|---:|---:|---:|---:|
| `chain.onBlock` | … | … | … | … | … | 800ms |
| `chain.produceBlock` | … | … | … | … | … | 800ms |
| `chain.onGossip` | … | … | … | … | … | 800ms |
| `chain.onInterval` | … | … | … | … | … | 800ms |
| `fc.aggregate` | … | … | … | … | … | 800ms |
| `fc.acceptNewAttestations` | … | … | … | … | … | 400ms |

Quick analysis recipe:

```bash
# Counts and percentiles per probe (requires GNU `datamash` or pipe to awk)
awk -F'\t' 'NR>1 {print $2 "\t" $3}' <date>-<sha>-slot_probe.tsv \
    | sort \
    | uniq -c
```

Findings: <2-4 sentences>.

## 2. Chain-worker queue saturation

Source: scrape of `lean_chain_queue_depth{queue="block"|"attestation"}` from
`http://<zeam_0_ip>:8000/metrics` if you ran the scrape loop, or eyeballed
from grafana.

- Max block queue depth: <N> / <capacity>
- Max attestation queue depth: <N> / <capacity>
- Time periods above 50% capacity: <list timestamps>
- Any `lean_chain_queue_dropped_total` increments: <yes / no>

Findings: <2-4 sentences>.

## 3. IO-thread invariant

`#803` invariant: the libxev main thread runs *only* the event router —
no STF, no XMSS verify, no aggregation. To check, identify the libxev TID
in the zeam_0 log (search for `libxev main thread tid=`) and look in
`flamegraph.svg` for that TID. The forbidden symbol set:

- `apply_raw_block` / `apply_transition`
- `verifySsz` (XMSS verify)
- `AggregatedSignatureProof.aggregate`
- `process_block` / `process_slots`
- `hashTreeRoot`

Observation: <samples landing on libxev TID in forbidden set / total libxev samples>
= <pct>%. Anything above ~0.1% is a violation worth filing.

Findings: <2-4 sentences>.

## 4. Lock contention

Top callers of `pthread_mutex_lock` / `__psynch_cvwait` / `_pthread_cond_wait`
in `flamegraph.svg`:

| Caller | Approx % of total samples |
|---|---:|
| <e.g. forkchoice.onAttestation → state_lock> | <pct> |
| <e.g. chain.onBlock → block_cache_lock> | <pct> |
| <e.g. node.onGossip → events_lock> | <pct> |

Findings: <2-4 sentences>.

## Headline findings (bullet form, action-oriented)

- <e.g. "fc.aggregate exceeds budget 14% of slots — confirms aggregation must move off chain-worker thread or run async">
- <e.g. "block queue saturated only during fork-period bursts; sized correctly for steady-state">
- <e.g. "no IO invariant violations observed → slice (c) holds in steady-state">
- <e.g. "top lock contention is `state_lock` on attestation path → candidate for arena allocator refactor">

## Reproducibility

```bash
# 1. Start devnet (separate shell)
cd lean-quickstart
NETWORK_DIR=local-devnet ./spin-node.sh \
    --node zeam_0,zeam_1,zeam_2,zeam_3 \
    --generateGenesis

# Wait ~60 seconds for gossip mesh

# 2. Capture
scripts/devnet-profile/capture.sh "zeam.*zeam_0" 1800 \
    docs/perf/devnet/raw/$(date +%F)/

# 3. Extract probes from log (parser is portable across BSD awk + gawk)
LOG=lean-quickstart/local-devnet/data/zeam_0/stderr.log
grep "slot_probe over budget" "$LOG" \
    | awk -f scripts/devnet-profile/parse-slot-probes.awk \
    > docs/perf/devnet/baselines/$(date +%F)-slot_probe.tsv
```

Raw `perf.data` (~300-500 MB) is in `docs/perf/devnet/raw/`, gitignored.
`flamegraph.svg` and `slot_probe.tsv` are alongside this summary file.
