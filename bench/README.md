# bench/

Top-level zbench harness for zeam. See
`docs/superpowers/specs/2026-05-12-perf-profile-bench-design.md` for design rationale.

## Targets

| Binary | Source | Coverage |
|---|---|---|
| `bench-xmss` | `xmss_bench.zig` | XMSS PROD verify (single + batch_32), sign |
| `bench-stf` | `stf_bench.zig` | `apply_raw_block`, `apply_transition` |
| `bench-aggregation` | `aggregation_bench.zig` | `AggregatedSignatureProof.aggregate` (gossip-only + with-children) |
| `bench-forkchoice-ssz` | `forkchoice_ssz_bench.zig` | `ForkChoice.{onBlock,onAttestation}`, SSZ block/state encode/decode |
| `bench-smoke` | `smoke_bench.zig` | Build harness smoke test |

## Running

```sh
zig build bench               # all targets
zig build bench-xmss          # single target
```

All bench binaries are built `ReleaseFast` regardless of `-Doptimize=...`. Debug-mode numbers are noise.

## Profiling

```sh
scripts/profile.sh xmss       # samply on macOS, perf on linux
```

Profile artifacts land under `docs/perf/profiles/` (gitignored).

## Baselines

Last captured zbench reports live in `docs/perf/baselines/<target>.txt`. Refresh
procedure in `docs/perf/README.md`.

## Conventions

- All bench fixtures are **deterministic** (`bench/common/rng.zig` for synthetic, leanSpec test vectors for STF). Numbers must be reproducible across machines.
- `ReleaseFast` is the only meaningful optimize mode for bench.
- Each bench's `main` does setup once before `bench.run(...)`. Per-iteration bodies do only the measured operation.
