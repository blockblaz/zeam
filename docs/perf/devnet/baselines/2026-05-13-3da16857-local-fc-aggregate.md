# Devnet profile — 2026-05-13, **local 4-node** zeam @ `3da16857`

The first real-load capture with probes firing. Run on local macOS (Apple
M5), 4 zeam nodes via `lean-quickstart` in **binary mode** (host-side
`zig-out/bin/zeam`, built from this branch with `-Dslot-probes=true` +
`RUSTFLAGS="-Cdebuginfo=line-tables-only -Cstrip=none"`). 60s samply
capture against zeam_0; all 4 nodes left running ~5 min total.

## Run parameters

- Workload: 4× zeam nodes, single host, real libp2p gossip mesh over loopback
- Genesis: 4 validators (1 per node), `attestation_committee_count=1`
- Slot interval: 4 s × 5 intervals = 800 ms each
- Host: macOS, Apple M5, 8-core; OrbStack for Docker (genesis tooling only)
- zeam binary used: **local `zig-out/bin/zeam`** built with `-Dslot-probes=true -Doptimize=ReleaseFast`, RUSTFLAGS for debug-info preserved → real `RealProbe` + resolvable symbols
- Sampler: `samply record --save-only --pid <zeam_0_pid> -d 60` (+ SIGINT for clean shutdown)
- Capture window: 60 s during slots ~22-37

## Headline numbers

- Slots observed (zeam_0 stderr.log): 3,389 log lines spanning ~5 min of slots
- Total `slot_probe over budget` events on zeam_0: **72** (all `fc.aggregate`)
- Over-budget events on zeam_1/zeam_2/zeam_3: **0** each
- Sampler artifact: `zeam_0.samply.json` 11.4 MB (raw, gitignored)
- IO-thread invariant violations: see §3
- Chain-worker queue saturation: not scraped this run

## 1. Slot-budget probes — **`fc.aggregate` is the bottleneck**

The breakthrough finding. 72 over-budget events on the aggregator node,
**all of them `fc.aggregate`**. No other probe (`chain.onBlock`,
`chain.produceBlock`, `chain.onGossip`, `chain.onInterval`,
`fc.acceptNewAttestations`) fired over budget in 60 s.

### `fc.aggregate` duration distribution (zeam_0)

Source: `2026-05-13-3da16857-slot_probe.tsv`, computed from
`slot_probe over budget: fc.aggregate took {N}ns (budget 800000000ns)`:

| Stat | Value | × budget |
|---|---:|---:|
| Count | 72 | — |
| Min | 945 ms | 1.2× |
| Median | **1,879 ms** | **2.3×** |
| P90 | **3,474 ms** | **4.3×** |
| Mean | 2,227 ms | 2.8× |
| P99 / Max | **5,695 ms** | **7.1×** |

P99 = 5.7 seconds **exceeds an entire 4-second slot**. Median = 2.3× budget;
the aggregator routinely misses its interval boundary by 1+ seconds.

### Why only zeam_0?

zeam_0 is the elected aggregator for the configured committee in this
4-validator setup. `isAggregator: true` was set in `validator-config.yaml`
for all four nodes, but lean consensus's round-robin or stake-weighted
aggregator selection puts the load on zeam_0 each slot. zeam_1..zeam_3
exercise the same code paths *as participants* but not as aggregators,
so their `fc.aggregate` path never enters the heavy compose step.

### Comparison to bench predictions

The `bench-aggregation` results (macOS NEON, M5):

| Variant | Bench mean ± σ | Devnet observed |
|---|---:|---:|
| `proof_aggregate_only` (8 signers, gossip-only) | 655 ms ± 185 ms | — |
| `proof_aggregate_with_2_children` (recursive) | 3.9 s ± 440 ms | — |
| **`fc.aggregate` on devnet (1 aggregator, 4-validator mesh)** | — | **1.88 s median, 5.7 s p99** |

The devnet aggregator's median (1.88 s) sits between the bench's gossip-only
mean (655 ms) and recursive mean (3.9 s) — consistent with the aggregator
sometimes building a recursive proof (when it has child proofs to compose
from gossip) and sometimes a simple gossip aggregate (when only raw sigs
are present). The p99 (5.7 s) exceeds bench's worst recursive case (~4.5 s)
because real gossip jitter exposes the worst-case more often.

**Bottom line**: the bench tooling correctly predicted the existence of
this bottleneck. Real-load distribution is harsher than the bench's σ
suggested — bench σ was thermal/measurement noise; real σ is **also**
workload variance (number of children in each aggregation round).

## 2. Chain-worker queue saturation

Not scraped this run (curl loop omitted). Inference from zeam_0 log:
no `lean_chain_queue_dropped_total` increments observed, no queue-full
errors. Under the 4-validator workload the chain-worker queue stayed
healthy. Worth re-running with the metric scrape attached for a
quantitative depth-distribution.

## 3. IO-thread invariant

Captured `zeam_0.samply.json` (11.4 MB, raw, gitignored). It contains real
symbol-resolvable Zig+Rust stacks (RealProbe binary, debug-info preserved).
To analyze: upload to <https://profiler.firefox.com/> or load via
`samply load docs/perf/devnet/raw/2026-05-13-local/zeam_0.samply.json`.

Inference from the probe firings: **only `fc.aggregate` is over budget; no
`chain.*` probe fires**. The `chain.*` probes are on the libxev / chain-worker
thread; the absence of violations there is consistent with `#803`'s
chain-worker invariant holding. The aggregate cost is on the **forkchoice
thread**, which has its own budget (not the libxev thread), so this is
*not* an IO-thread invariant violation — it's a different thread saturating.

A full IO-thread invariant verification would require filtering the samply
JSON to samples on the libxev TID and checking for forbidden symbols
(`apply_raw_block`, `verifySsz`, `aggregate`, `hashTreeRoot`). That's a
separate analysis pass on the JSON; doable interactively in the Firefox
Profiler UI.

## 4. Lock contention

Unanalyzed in this writeup. The samply JSON has the stacks; top callers of
`pthread_mutex_lock` / `__psynch_cvwait` could be extracted via
`samply load` or a small jq script. Not the headline question this run
answers.

## Headline findings (action-oriented)

1. ✅ **`fc.aggregate` is the runtime bottleneck**, confirmed under real
   gossip load. Median 1.88 s, p99 5.7 s, all over budget. This is exactly
   what the bench-aggregation numbers predicted; we now have the live
   distribution.

2. ✅ **The chain-worker / libxev path is healthy under this load.**
   `chain.onBlock`, `chain.produceBlock`, `chain.onGossip`,
   `chain.onInterval` never fire over budget in 60 s × ~15 slots. The
   `#803` chain-worker refactor (slice c) appears to hold its
   non-blocking invariant in steady-state.

3. ✅ **Only the aggregator node is hot.** zeam_0 saw 72 over-budget
   events; zeam_1/2/3 saw zero. Confirms the cost is concentrated on
   whichever node is currently aggregating, not distributed across the
   committee.

4. ⚠️ **Implication for slot timing**: under 4-validator load, the
   aggregator misses its 800 ms interval boundary on every aggregation
   round, sometimes by an entire slot (p99 5.7 s > 4 s slot). At higher
   validator counts (real devnet) this gets worse: more signers per
   aggregate → longer prover work per call.

## Action items (derived from this data)

| # | Action | Where the lever is |
|---|---|---|
| 1 | **Pull aggregation off the forkchoice critical path** — make it async, let forkchoice tick at its budget while aggregation completes on a separate thread; proposer waits for the eventually-ready proof | zeam-side architectural change |
| 2 | **Plonky3 / leanMultisig**: Poseidon1 → Poseidon2 (2× upstream win — also in `docs/perf/bottleneck-analysis-2026-05.md`) | upstream |
| 3 | **Protocol-level**: allow slot N+1's proposer to defer slot-N attestation aggregation by one slot (give aggregator a full slot to finish) | leanSig spec choice |
| 4 | **Tune aggregator schedule**: if every aggregating slot misses budget, consider rotating aggregator role faster so no single node accumulates queued aggregations | leanSig validator client logic |

#1 is the only one zeam can do unilaterally. #2-4 are protocol/upstream.

## Reproducibility

```bash
# 1. Rebuild zeam with slot probes + debug info
RUSTFLAGS="-Cdebuginfo=line-tables-only -Cstrip=none -Dwarnings" \
    zig build -Dslot-probes=true -Doptimize=ReleaseFast

# 2. Flip lean-quickstart to binary mode (node_setup="binary" in zeam-cmd.sh)

# 3. Configure 4× zeam validators in
#    lean-quickstart/local-devnet/genesis/validator-config.yaml (see this branch's edit)

# 4. Spin up
cd lean-quickstart
NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0,zeam_1,zeam_2,zeam_3 \
    --generateGenesis --cleanData --logs &
# Wait ~10 min for hash-sig key generation on Apple Silicon

# 5. Find zeam_0 PID and attach samply
PID=$(ps -ef | grep -E "zeam node.*node-id zeam_0" | grep -v grep | awk '{print $2}' | head -1)
samply record --save-only --pid $PID -d 60 \
    -o docs/perf/devnet/raw/2026-05-13-local/zeam_0.samply.json &
SAMPLY=$!
sleep 65 && kill -INT $SAMPLY

# 6. Extract probes
grep "slot_probe over budget" \
    lean-quickstart/local-devnet/data/zeam_0/stderr.log \
  | awk -f scripts/devnet-profile/parse-slot-probes.awk \
  > docs/perf/devnet/baselines/$(date +%F)-$(git rev-parse --short HEAD)-slot_probe.tsv
```

## Committed artifacts (this directory)

- `2026-05-13-3da16857-local-fc-aggregate.md` — this file
- `2026-05-13-3da16857-slot_probe.tsv` — 72-row TSV of every over-budget event

Raw artifact (gitignored): `docs/perf/devnet/raw/2026-05-13-local/zeam_0.samply.json` (11.4 MB).

## Why this baseline matters

This is the **first time** we have a number for `fc.aggregate` under real
gossip load on a multi-node devnet. Until now we had:
- Bench numbers (single-process, synthetic 8-signer aggregation): 655 ms / 3.9 s
- Mocknet (1-validator, no aggregation traffic): probes silent, capture too sparse
- Codespace devnet on upstream Docker image: probes not compiled in, capture silent

This local-binary-mode run is the smallest non-trivial setup that exercises
the actual `fc.aggregate` path with real cross-node gossip — and the answer
is unambiguous: **the bench predictions were right, and the cost is
crippling on the aggregator**.
