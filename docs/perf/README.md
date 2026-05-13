# Performance — bench + profile

Bench targets live in `bench/`. Profile artifacts (`.samply.json`,
`.perf.data`, `.svg`) are gitignored globally — keep them locally or
ship them to object storage; don't commit.

## Running benches

```sh
zig build bench                   # all targets (smoke + xmss + stf + aggregation + forkchoice-ssz)
zig build bench-xmss              # single target
```

To track regressions, keep your previous run's output around and compare:

```sh
zig build bench-aggregation 2>/dev/null > /tmp/agg-before.txt
# ... make changes ...
zig build bench-aggregation 2>/dev/null > /tmp/agg-after.txt
diff /tmp/agg-before.txt /tmp/agg-after.txt
```

There is no committed baseline file and no automated regression gate (by
design — bench numbers are machine-specific and would noise-diff on every
PR). Headline numbers worth preserving belong in PR descriptions or
commit messages.

## Profiling a bench binary

```sh
scripts/profile.sh bench xmss       # samply (macOS) / perf (Linux)
```

Output goes to `docs/perf/profiles/<name>.samply.json` (or `.perf.data` +
`.svg` on Linux). Open the JSON at <https://profiler.firefox.com/> or view
the SVG in a browser.

Required tools:
- **macOS:** `cargo install samply` (one-time).
- **Linux:** `perf` (linux-tools package). For flamegraph SVG output:
  `git clone https://github.com/brendangregg/FlameGraph` and add the scripts to PATH.

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
scripts/profile.sh attach "zeam.*node" /var/lib/zeam-perf/

# macOS local validation
scripts/profile.sh attach "zeam.*node_id zeam_0" ./perf-out/
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
scripts/profile.sh slice /var/lib/zeam-perf/perf.data.20260513120000 12.3 14.5 slow-slot.svg
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
