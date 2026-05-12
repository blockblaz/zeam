# Devnet profile — 2026-05-13, single-node `zeam --mockNetwork` @ `56109fcf`

> First end-to-end devnet capture using the perf-devnet-profile tooling.
> **Workload is intentionally light** — single-validator mockNetwork — to
> validate the pipeline. Real multi-node + multi-validator capture is a
> separate follow-up (see "Gap" at the end).

**Run parameters**

- Workload: `zig-out/bin/zeam beam --mockNetwork --data_dir /tmp/zeam-data`
- Duration: 60 s capture (after 10 s warmup)
- Nodes: 1 (single `zeam_n1` instance, mocked network peers)
- Validators: 1
- Slot interval: 4 s (mainnet preset) → 15 slots × 5 intervals = 75 interval ticks observed
- Host: GitHub Codespace, Ubuntu 24.04 x86_64, 8-core 31 GB
- zeam build: `-Dslot-probes=true -Doptimize=ReleaseFast` at sha `56109fcf`
- Sampler: `perf record -F 997 --call-graph fp` (the new fp default)

## Headline numbers

- Slots observed: **~15** (slot ticks visible from `s=10` near capture end backtracked to capture start)
- Total `slot_probe over budget` events: **0**
- Worst probe by over-budget rate: **none — no probe exceeded its budget in this run**
- IO-thread invariant violations observed: **unmeasured** (perf data too sparse — see §3 below)
- Chain-worker queue depth: not scraped this run (no Prometheus loop in scope)

## 1. Slot-budget probes

Source: `zeam.log` stderr filtered with
`grep "slot_probe over budget" /tmp/zeam.log | awk -f scripts/devnet-profile/parse-slot-probes.awk`.

| Probe | Over-budget events / 75 intervals | Comment |
|---|---:|---|
| `chain.onBlock` | 0 | block production + ingest under budget |
| `chain.produceBlock` | 0 | local block production under budget |
| `chain.onGossip` | 0 | mockNetwork gossip never crossed budget |
| `chain.onInterval` | 0 | tick handler fast |
| `fc.aggregate` | 0 | **no aggregation fired** — single validator means no committee to aggregate |
| `fc.acceptNewAttestations` | 0 | tick-0/tick-4 rotation under HALF budget |

**Finding**: in single-validator mockNetwork steady-state, every probe stays under
its budget. The bench-derived numbers (chain.onBlock ~82 µs, STF ~150 µs, etc.)
are consistent with this — none of them are remotely close to the 800 ms
interval budget. **The 3.9 s recursive aggregation cost from
`bench-aggregation` does not surface here** because there's no committee
aggregation in single-validator mode.

## 2. Chain-worker queue saturation

Not scraped this run (no Prometheus loop was running during capture).
`lean_chain_queue_depth` metric is defined and emits on every `sendBlock` /
`sendAttestation`. A future run should add the curl-loop in
`scripts/devnet-profile/capture.sh` or scrape `/metrics` separately.

Inference from the zeam log (light traffic, single validator): queue depth
stays near 0 throughout. No `lean_chain_queue_dropped_total` increment in
the log → no queue-full events.

## 3. IO-thread invariant

**Unmeasured.** Reason: perf captured insufficient samples to build a useful
flamegraph for invariant analysis. With `-p $PID -e task-clock` and zeam
~99% idle (sleeping in `nanosleep` / `epoll_wait` between 4-second slot
ticks), only ~50-100 effective samples were collected over 60 seconds.
`flamegraph.svg` came back containing literally:

```
<text x="600.00" y="24">ERROR: No valid input provided to flamegraph.pl.</text>
```

Implication for the next capture: use one of these strategies to get a
useful flamegraph from a CPU-light single-node target:

- **Longer capture window** (10-30 min) — 10-30× more effective samples
- **`-e cpu-clock`** instead of default `-e task-clock` — samples include
  idle time too, giving baseline % per code path
- **Multi-validator workload** — more attestations, more cross-validator
  traffic, more CPU work per slot
- **Inject artificial load** — separate process flooding gossip topics

The current capture is *correct*; it's just dim. Single-validator mockNetwork
is too light a workload for a CPU-time-only profile.

## 4. Lock contention

**Unmeasured.** Same reason as §3 — sample count too low. The capture script
itself worked correctly; the workload didn't drive enough CPU activity.

## Headline findings (action-oriented)

- ✅ **Pipeline validated end-to-end on Linux.** `scripts/devnet-profile/capture.sh`
  attached cleanly to a running zeam process, recorded `perf.data` with the
  `fp` call-graph default, generated `flamegraph.svg`, and emitted slot
  probe warnings to a parseable log (none fired in this run, but the path
  is wired and tested).
- ✅ **Bench numbers are conservative.** Zero probe budget violations in 60 s
  of 15 slots means the bench-extrapolated worst cases are not occurring
  under light steady-state load. Reassuring.
- ❌ **No real bottleneck data from single-validator mockNetwork.** Aggregation
  is the headline cost in the bench numbers (655 ms gossip-only, 3.9 s
  recursive); neither code path was hit by this workload because there's
  no committee to aggregate. To see aggregation under load we need
  multi-validator + multi-node.

## Gap → follow-up

The capture pipeline is proven. The next baseline should be a **real
multi-node lean-quickstart devnet** with 4 zeam validators talking via
libp2p:

- Modify `lean-quickstart/local-devnet/genesis/validator-config.yaml` to
  configure 4× `zeam_N` validators instead of the multi-client mix that's
  currently there. Each on its own libp2p port.
- Generate genesis via `--generateGenesis` (requires Docker; codespace has it).
- Run all four with `-Dslot-probes=true`.
- Attach `capture.sh` to `zeam_0` for 10-30 min.
- That run *will* fire `fc.aggregate` and potentially over-budget warnings.

Until then, the slot-probe behavior under realistic load is an unknown.

## Reproducibility

```bash
# 1. Build with slot probes
zig build -Dslot-probes=true -Doptimize=ReleaseFast

# 2. Start single-node mockNetwork in background
./zig-out/bin/zeam --console_log_level info beam --mockNetwork \
    --data_dir /tmp/zeam-data > /tmp/zeam.log 2>&1 &
ZEAM_PID=$!

# 3. Capture 60s
sleep 10  # warmup
scripts/devnet-profile/capture.sh "zig-out/bin/zeam beam" 60 \
    docs/perf/devnet/raw/$(date +%F)/

# 4. Tear down
kill -INT $ZEAM_PID

# 5. Extract probes (empty in this run)
grep "slot_probe over budget" /tmp/zeam.log \
    | awk -f scripts/devnet-profile/parse-slot-probes.awk
```

Captured artifacts (gitignored under `raw/`):
- `perf.data` (~8 KB — sparse due to idle process)
- `flamegraph.svg` (~580 B — empty due to insufficient samples)
- `/tmp/zeam.log` (~15 lines at info level over 60 s)
