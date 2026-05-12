# Devnet profile — 2026-05-13, 4-node lean-quickstart @ `664c83a3`

Second devnet capture using the perf-devnet-profile tooling. **Real
multi-node devnet, real cross-node gossip** — but a critical caveat
surfaced: lean-quickstart spawned zeam from the **upstream Docker image**
`blockblaz/zeam:devnet4`, not our perf-devnet-profile branch build. So the
slot probes never compiled in and the binary was stripped. Findings about
the tooling are solid; findings about zeam internals are out of reach
without a custom Docker image.

## Run parameters

- Workload: 4× zeam nodes via `lean-quickstart` Docker deployment, mesh
  of 4 validators (1 per node, `count: 1`, total committee = 4)
- Duration: 60 s capture window after ~9 min steady-state warmup
- Genesis: hash-sig keys (XMSS PROD scheme) generated via
  `hash-sig-cli` Docker tool, ~12 minutes
- Slot interval: 4 s (mainnet preset) → ~15 slots × 5 intervals
- Host: GitHub Codespace, Ubuntu 24.04 x86_64, 8-core 31 GB
- zeam binary used: **`blockblaz/zeam:devnet4` (prebuilt upstream image)** —
  NOT this branch's build at `zig-out/bin/zeam`
- Sampler: `sudo perf record -F 997 --call-graph fp -p <host-pid>`

## Headline numbers

- Slots observed (zeam_0 stderr.log): 4,389 log lines, slots ~20-30 visible
- Total `slot_probe over budget` events: **0**
  - But probes are not in this binary — the count says nothing about the
    actual workload's probe behavior
- Total perf samples (60 s, zeam_0 only): **49,493** (4.0 MB `perf.data`)
- zeam_0 CPU utilization (9 min wall, 7 min CPU): **~76% — genuinely busy**
- All 4 nodes have **3 gossip mesh peers** (full mesh)
- Chain-worker queue depth (block / attestation): 1 / 1 (light, no saturation)

## 1. Slot-budget probes

**Unmeasured.** The deployed binary
`blockblaz/zeam:devnet4` was built without `-Dslot-probes=true`, so
`pkgs/utils/src/slot_probe.zig` is `NoopProbe` and emits zero log lines.
The 0-count from `grep "slot_probe over budget" stderr.log` is therefore
not a real "no violations" finding — it's "probes don't exist in this build."

To get real probe data we need a **custom-built Docker image** from this
branch with `-Dslot-probes=true` baked in. See "Gap → follow-up" below.

## 2. Chain-worker queue saturation

Scraped from each node's `/metrics` endpoint mid-capture:

```
port 8081: lean_chain_queue_depth{queue="block"} 1
           lean_chain_queue_depth{queue="attestation"} 1
port 8082: lean_chain_queue_depth{queue="block"} 1
port 8083: lean_chain_queue_depth{queue="block"} 1
port 8084: lean_chain_queue_depth{queue="block"} 1
```

Queue depth at 1 (single in-flight message) across all nodes — **no
saturation** under this small-committee workload. No
`lean_chain_queue_dropped_total` increments observed.

## 3. IO-thread invariant

**Unanalyzable from this profile.** Symbols stripped. Top samples by
frame chain:

| Stack (top→leaf, leaf-bytes-resolved) | Sample weight | % of zeam |
|---|---:|---:|
| `zeam;[unknown];[zeam];[zeam]` | 11.32G cycles | ~22% |
| `zeam;[zeam]` | 10.88G | ~21% |
| `zeam;[zeam];[zeam]` | 10.61G | ~20% |
| `zeam;[unknown];[zeam]` | 5.70G | ~11% |
| Other zeam-self frames | — | ~9% |
| `zeam;__sched_yield;[kernel.kallsyms]` (×7 variants) | ~4.5G | ~5% |
| Other syscalls (`syscall`, `futex` paths) | — | ~3% |

**The shape says zeam is compute-bound (>80% in its own code) and not
blocking on locks/sleep/IO** (~5% `__sched_yield`, ~3% other kernel
syscalls). We can't say *what* it's computing without symbols — but we
can rule out "stuck on a mutex" as the dominant cost.

## 4. Lock contention

Unmeasurable. `pthread_mutex_lock` / `__psynch_cvwait` / `_pthread_cond_wait`
don't appear in the resolved frames at meaningful weight. Either:
(a) zeam's locks are well-uncontended at this load
(b) the unidentified `[zeam]` frames internally include lock operations
    that we can't separate without symbols

The `__sched_yield` weight (~5% total) is a weak signal of cooperative
yielding inside zeam — possibly libxev's spin-then-yield pattern, possibly
a rayon worker giving up its slice. Without symbols, can't disambiguate.

## Headline findings (action-oriented)

1. ✅ **Tooling validated against a real multi-node devnet.** The full chain
   from `lean-quickstart` startup → 4-node mesh → perf attach via
   `sudo docker top zeam_0` → 49K-sample flamegraph → log parsing → metric
   scrape works end-to-end on a GitHub Codespace.

2. ✅ **zeam is compute-bound under steady-state load**, not lock/IO-bound.
   Top 4 stacks (74% of samples) live in zeam's own code; only ~5% in
   sched_yield, ~3% in other syscalls. Whatever the dominant cost is, it's
   in the application logic, not in the system layer.

3. ❌ **We don't know which zeam function is hot** because the deployed
   Docker image is stripped. The 49K samples are real but symbol-less.

4. ❌ **Slot-probe data is unobtainable from this run** because the deployed
   binary doesn't have probes. The 0-event count is a "false negative" — we
   can't conclude anything about probe behavior under this workload.

5. ✅ **No queue saturation, no dropped messages**, full mesh, healthy
   metrics. The 4-node × 4-validator workload is light by design (each
   committee has only 4 sigs to aggregate; no recursive aggregation
   triggered).

## Gap → follow-up

To turn this into a real bottleneck analysis we need either:

**Option A — Custom Docker image** (recommended):
1. Add a `Dockerfile.perf` to the repo that copies in our
   `zig-out/bin/zeam` (built with `-Dslot-probes=true -Doptimize=ReleaseFast`
   and a Rust profile keeping symbols / `strip = "none"`)
2. `docker build -t blockblaz/zeam:perf-devnet -f Dockerfile.perf .`
3. Patch `lean-quickstart` to use the `:perf-devnet` tag (or override via
   `--tag perf-devnet` if spin-node.sh supports it)
4. Re-run this capture; expect probes to fire and stacks to resolve

**Option B — Binary deployment mode**:
`lean-quickstart` may support running zeam from a host-side binary rather
than via Docker. Investigate `spin-node.sh` for that path; would avoid
the image-rebuild cycle.

**Option C — Multi-validator workload** (orthogonal): the current run uses
4 validators total (1 per node). To exercise the bench-aggregation
findings (655 ms gossip-only with 8 signers, 3.9 s recursive), we need
≥ 8 validators per committee, which means 8+ validators with `count: N`
in `validator-config.yaml`. Key generation cost: ~3 min per validator
(we observed ~12 min for 4 validators in this run; 8 validators = ~25 min).

## Codespace gotchas discovered this session (new)

In addition to the six already documented in `docs/perf/devnet/README.md`:

7. **`/usr/local/bin/yq` (Go yq) must be ahead of `/home/codespace/.python/current/bin/yq` (Python yq) in PATH.** lean-quickstart uses mikefarah/yq syntax (`yq eval '.x' file.yaml`); Python yq uses different filter syntax and breaks on the same call. Fix: `export PATH=/usr/local/bin:$PATH` before running spin-node.sh.

8. **`--cleanData` wipes `hash-sig-keys/` too**, forcing full re-generation. If you want to re-spin a devnet without burning 12+ min of key gen, drop `--cleanData` and clean only `local-devnet/data/<node>/` manually.

9. **lean-quickstart's deploy mode reads the YAML's `deployment_mode: local`
   field** but still uses the upstream Docker image. There's no built-in
   "use my locally-built binary" flag (without further patching). This
   is the root cause of finding #3/#4 above.

## Reproducibility

```bash
# 1. Setup yq + perf + sysctl (see docs/perf/devnet/README.md prereqs)
export PATH=/usr/local/bin:$HOME/zig-0.16:$HOME/.cargo/bin:$PATH
sudo sysctl -w kernel.perf_event_paranoid=1

# 2. Configure 4-zeam validator-config.yaml (one per node, count: 1)
# (See diff to local-devnet/genesis/validator-config.yaml in this run)

# 3. Spin up
cd lean-quickstart
NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0,zeam_1,zeam_2,zeam_3 \
    --generateGenesis --cleanData --logs &
# Wait ~12 min for key generation + node spawn

# 4. Capture (use docker top to find the inner-container zeam PID at host level)
PID=$(sudo docker top zeam_0 | awk 'NR>1 {print $2}' | head -1)
sudo perf record -F 997 --call-graph fp -p $PID \
    -o docs/perf/devnet/raw/2026-05-13/perf.data -- sleep 60
sudo chown $USER docs/perf/devnet/raw/2026-05-13/perf.data
perf script -i docs/perf/devnet/raw/2026-05-13/perf.data \
    | stackcollapse-perf.pl | flamegraph.pl \
    > docs/perf/devnet/baselines/2026-05-13-<sha>-flamegraph.svg

# 5. Probes (this run: empty because Docker image lacks slot probes)
LOG=lean-quickstart/local-devnet/data/zeam_0/stderr.log
grep "slot_probe over budget" "$LOG" \
    | awk -f scripts/devnet-profile/parse-slot-probes.awk
```

Captured artifacts (gitignored):
- `perf.data` 4.1 MB, 49,493 samples
- `flamegraph.svg` 108 KB (symbol-less due to upstream Docker image strip)
- `folded.txt` 98 KB, 455 unique stacks
- `zeam_0/stderr.log` 4,389 lines

This is the FIRST real multi-node devnet baseline despite the limitations.
Future runs against a custom-built image (Option A) will produce actionable
data on top of this scaffolding.
