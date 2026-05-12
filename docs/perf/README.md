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

## Slot-budget probes

In-process timers in `chain.zig` / `forkchoice.zig` log when an interval exceeds
budget. Off by default; enable with:

```sh
zig build -Dslot-probes=true
zig build test -Dslot-probes=true
```

When over budget, logs:
- `slot_probe over budget: <name> took Xns (budget Yns)` — warning level

Call sites:

| File | Function | Probe name | Budget |
|---|---|---|---|
| `chain.zig` | `onBlock` | `chain.onBlock` | `INTERVAL_BUDGET_NS` (800ms) |
| `chain.zig` | `produceBlock` | `chain.produceBlock` | `INTERVAL_BUDGET_NS` |
| `chain.zig` | `onGossip` | `chain.onGossip` | `INTERVAL_BUDGET_NS` |
| `chain.zig` | `onInterval` | `chain.onInterval` | `INTERVAL_BUDGET_NS` |
| `forkchoice.zig` | `aggregateUnlocked` | `fc.aggregate` | `INTERVAL_BUDGET_NS` |
| `forkchoice.zig` | `acceptNewAttestationsUnlocked` | `fc.acceptNewAttestations` | `HALF_INTERVAL_BUDGET_NS` (400ms) |

The probe module lives at `pkgs/utils/src/slot_probe.zig`. With probes off (default),
`NoopProbe` compiles away to nothing — production builds pay zero cost.
