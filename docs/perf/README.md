# Performance — bench + profile

Bench targets live in `bench/`. Profile artifacts (gitignored except `notes.md`)
land here under `profiles/`. Committed baselines live under `baselines/`.

See `docs/superpowers/specs/2026-05-12-perf-profile-bench-design.md` for design.

## Running benches

```sh
zig build bench                   # all targets (smoke + xmss + stf + aggregation + forkchoice-ssz)
zig build bench-xmss              # single target
```

## Profiling

```sh
scripts/profile.sh xmss           # samply (macOS) / perf (linux)
```

Open `docs/perf/profiles/<target>.samply.json` in Firefox Profiler
(`https://profiler.firefox.com/`) or view the perf SVG in a browser.

Required tools:
- **macOS:** `cargo install samply` (one-time).
- **Linux:** `perf` (linux-tools package). For flamegraph SVG output:
  `git clone https://github.com/brendangregg/FlameGraph` and add the scripts to PATH.

## Refreshing a baseline

```sh
zig build bench-<name> 2>/dev/null > docs/perf/baselines/<name>.txt
git diff docs/perf/baselines/<name>.txt    # eyeball the change
git add docs/perf/baselines/<name>.txt
git commit -m "bench: refresh <name> baseline (<reason>)"
```

The git diff is the regression detector. There is no automated regression gate
(by design — see spec § Non-goals).

## Production profiling — continuous low-rate capture

For real multi-server deployments, attach a sampling profiler to each running
zeam node and keep recording. No code changes — `perf` (Linux) and `samply`
(macOS) attach to the process by PID. Pair with a sidecar uploader that
ships rotated chunks to object storage; correlate after the fact by joining
wall-clock to existing Prometheus metrics (`lean_committee_signatures_aggregation_time_seconds`,
`zeam_chain_onblock_duration_seconds`, etc.).

### Capture

```sh
# Linux production node (run under systemd for always-on capture)
scripts/profile-continuous.sh "zeam.*node" /var/lib/zeam-perf/

# macOS local validation
scripts/profile-continuous.sh "zeam.*node_id zeam_0" ./perf-out/
```

Defaults: 19Hz sampling, frame-pointer call graphs, 200MB chunk rotation
(Linux) or 5-minute chunks (macOS). Overhead is roughly 0.5% CPU. Tunable
via `PROFILE_FREQ_HZ`, `PROFILE_CHUNK_BYTES`, `PROFILE_CHUNK_SECS`,
`PROFILE_CALL_GRAPH`.

Output:
- Linux: `perf.data.<timestamp>` files rotated by `perf --switch-output`
- macOS: `samply-<epoch>.json` per chunk

Build with debug info preserved so symbols resolve cleanly:

```sh
RUSTFLAGS="-Cdebuginfo=line-tables-only -Cstrip=none" \
    zig build -Doptimize=ReleaseFast
```

### Analysis

When Prometheus shows a slow event at wall-clock T:

1. Find the chunk covering T (filename suffix = capture-start timestamp).
2. `perf script --header -i <chunk>` shows capture-start absolute time.
   Compute `T_rel = T - capture_start`.
3. Slice:

```sh
scripts/profile-slice.sh /var/lib/zeam-perf/perf.data.20260513120000 12.3 14.5 slow-slot.svg
```

For samply (macOS), upload the JSON to <https://profiler.firefox.com/>
and use the timeline slider to focus on the window of interest.

### Why no in-process probes

Earlier iterations included `-Dslot-probes` instrumentation around the
`chain.onBlock` / `fc.aggregate` hot paths to emit "over budget" warnings.
Removed: the same signal is already exposed by existing Prometheus
histograms (no code change needed to use), and the continuous-capture
approach above lets you investigate any past event — not just ones a probe
happened to flag.
