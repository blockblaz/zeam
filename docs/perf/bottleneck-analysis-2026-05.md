# zeam bottleneck analysis — 2026-05

Synthesis across the four micro-bench targets (xmss, stf, aggregation,
forkchoice+ssz) on both macOS (Apple M5, NEON) and Linux x86_64 (codespace,
AVX2). Sources:

- `docs/perf/baselines/{xmss,stf,aggregation,forkchoice_ssz}.txt` — committed bench numbers
- `docs/perf/profiles/notes.md` — per-target findings, including the symbolized
  aggregation profile (commit `80677fbe`)
- Linux validation 2026-05-13: bench-xmss perf capture on GitHub Codespace
  (x86_64 AVX2) producing the same top-frame distribution as macOS NEON

What this is: the **prioritized list of bottlenecks zeam can act on**, plus the
explicit list of bottlenecks zeam **cannot fix** (they live upstream in
leanMultisig/Plonky3 or in the protocol itself).

What this is **not**: a devnet-load profile. We don't yet have probe data from
a running multi-node devnet. That's the next phase. Until we do, IO-thread
invariant violations, lock contention under real concurrency, and chain-worker
queue saturation are unmeasured — listed below as "unknowns."

---

## Headline costs (single op, ReleaseFast)

| Op | macOS (M5, NEON) | Linux (codespace, AVX2) | Slot interval = 800 ms |
|---|---:|---:|:--|
| XMSS verify (single sig) | 509 µs | 656 µs | well under |
| XMSS verify (batch ×32) | 16.8 ms | 18.7 ms | well under |
| XMSS sign (single) | 1.5 ms | 1.85 ms | well under |
| STF `apply_raw_block` | 151 µs | not measured | well under |
| STF `apply_transition` (validateResult=false) | 102 µs | not measured | well under |
| ForkChoice `onBlock` (with reinit overhead) | 82 µs | not measured | well under |
| ForkChoice `onAttestation` | 98 µs | not measured | well under |
| SSZ encode block (2636 B) | 42 µs | not measured | well under |
| SSZ encode state (678 B) | 26 µs | not measured | well under |
| **Aggregation gossip-only (8 signers)** | **655 ms** | not measured | **~80% of budget** |
| **Aggregation recursive (2 children)** | **3.9 s** | not measured | **~5× budget — exceeds slot** |

Linux/x86_64 hits the **same hot frames** as macOS NEON — `p3_monty_31::poseidon1::Poseidon1InternalLayer::permute_state`, `keccak::keccak_p`, `p3_mds::karatsuba_convolution::*` — just via AVX2 instead of NEON. The cross-platform check confirms the analysis below is platform-independent.

---

## Bottleneck #1: aggregation — out of zeam's reach

**The single biggest cost in the whole pipeline.** ~655 ms for the cheap
case, 3.9 s for the recursive case. Even the cheap case eats 80% of an
800 ms interval budget; the recursive case literally cannot fit in a 4 s
slot.

### Breakdown (symbolized macOS profile, worker thread, 71 k samples)

| Category | Share | Function |
|---|---:|---|
| Poseidon1 internal layer (partial round) | **30%** | `p3_monty_31::aarch64_neon::poseidon1::Poseidon1InternalLayer::permute_state` |
| MDS karatsuba convolution | **22%** | `p3_mds::karatsuba_convolution::FieldConvolve::{negacyclic_conv8, conv8}` |
| Poseidon1 external layer (full round) | **14%** | `Poseidon1ExternalLayer::permute_state_{initial, terminal}` |
| Poseidon1Compress (top-level wrapper) | **12%** | `lean_prover::mt_symetric::permutation::Poseidon1KoalaBear16::compress_mut` |
| Keccak p1600 (Shake PRF) | 7% | `keccak::p1600` |
| Sum-check / multi-linear eval | 4% | Plonky3 polynomial commitment internals |
| Quintic-extension field mul | 3% | Plonky3 challenger |
| Shake PRF wrapper | 2% | `leansig::tweak_hash::poseidon::poseidon_replacement_sponge` |
| Other Plonky3 / leansig | 6% | |

**Combined Poseidon1-related: 78%** of the entire in-binary cost.

### What zeam can do: nothing of consequence

- ❌ **Allocator tuning**: 0.3% malloc. No room.
- ❌ **Thread parallelism**: σ < 3% across 10 rayon workers. Already balanced.
- ❌ **Rust target-cpu / SIMD flags**: aarch64-apple-darwin already enables `aes/sha2/sha3/neon`; x86-64-v3 already enables AVX2. The earlier "33% from target-cpu=native" A/B was within thermal-noise σ when re-tested.
- ❌ **STARK phase sync** (13% worker idle per worker): inherent to Plonky3's multi-phase prover. Phase boundaries are sequential by design.

### What can move it (all upstream — not zeam)

| Lever | Expected effect | Owner |
|---|---:|---|
| Plonky3 Poseidon1 → Poseidon2 | ~2× speedup (Poseidon2 has fewer rounds and a different structure) | leanMultisig protocol + Plonky3 |
| FFT-based negacyclic conv replacing Karatsuba | 5-20% on the 22% MDS slice | Plonky3 upstream |
| GPU prover backend (Plonky3 has one, leanMultisig hasn't wired it) | 5-10× | leanMultisig |
| Smaller invariant proof (`LOG_INV_RATE_TEST=1` instead of `PROD=2`) | ~2× for gossip path | leanMultisig protocol decision |
| Avoid recursive aggregation in proposer hot path | Up to 6× (the 3.9 s → 655 ms delta) | leanSig protocol design |

**Conclusion on aggregation**: from zeam's side it's a fixed-cost ZK prover
running on dedicated CPU. The only zeam-side question is *when to invoke it*
(scheduling), and even there the wall-clock can't be reduced enough to fit a
4 s slot. The earlier "pre-aggregate one slot ahead" idea I floated doesn't
work — slot N+1's proposer needs slot-N attestations that may still be
arriving at the start of N+1; pre-aggregation can't include them. The only
real fixes are (a) algorithmic speedup upstream or (b) protocol-level
relaxation of the inclusion deadline.

---

## Bottleneck #2: STF hash_tree_root — concrete zeam-side win

**~30% of STF cost**, measurable from the bench. Both `apply_raw_block` and
the validateResult-skipping `apply_transition` go through `process_block` and
`process_slots`; the delta between them (151 µs → 102 µs) is exactly the
post-block `hashTreeRoot(BeamState)` call.

### Why it's expensive

Hashing a `BeamState` recomputes Merkle roots for every subtree even though
**most subtrees don't change between adjacent slots**. The state's
`historical_block_roots`, `historical_state_roots`, `validators`, and (most
slots) `attestations` lists are stable across one slot transition; only
`slot`, `latest_block_header`, and a few attestation fields actually mutate.

### Fix (well-understood across beacon clients)

Caching subtree roots, invalidating only changed subtrees per slot. The
`pkgs/types/src/StateHashCache.zig` infrastructure already exists in zeam;
the question is whether `hashTreeRoot(BeamState)` actually goes through it
on the STF hot path. Bench data suggests it does **not** — the 30% measured
cost is consistent with a full re-hash.

### Expected effect

If subtree caching kicks in on the unchanged paths, STF drops from ~150 µs
to **20-30 µs** (the cost of just re-hashing the genuinely changed leaves).
That's ~5× on STF — meaningful if STF runs many times per slot under load,
which it does (every gossip block re-runs STF for fork-choice scoring).

### Suggested follow-up PR scope

1. Profile `apply_raw_block` more deeply: confirm `hashTreeRoot` is the
   dominant non-process_block cost.
2. Verify whether `StateHashCache` is wired into the STF path; if not, wire it.
3. Re-baseline bench-stf; expected `stf_apply_raw_block` drops from 151 µs
   to ~30-50 µs.

---

## Bottleneck #3: forkchoice — allocator-bound, modest zeam-side win

**`onBlock` ~82 µs, `onAttestation` ~98 µs**, both heavily including a
per-iteration `ForkChoice.init` cost the bench couldn't factor out cleanly.
Profile shows **no Rust FFI in the hot path** — pure Zig hash-map ops on
`protoArray.indices` and `AttestationTracker.{latestNew, latestKnown}`.

### What zeam can do

| Lever | Expected effect | Effort |
|---|---:|---|
| Pre-size hash-map capacities to `MAX_CACHED_BLOCKS = 1024` | Remove rehash-grow cost | trivial |
| Arena-backed allocator for per-slot intermediate state | Cut alloc cost on `onAttestation` | small-to-medium |
| Faster Zig hash-map (rather than `AutoHashMap`) for `Root → index` lookup | 10-20% on `onBlock` | medium |

Expected combined effect: forkchoice `onBlock` 82 µs → 40-50 µs, `onAttestation`
98 µs → 50-60 µs. Not headline numbers but easy to get and stable.

---

## Bottleneck #4: SSZ encode/decode — moderate win available

SSZ block encode at 42 µs for 2636 bytes = **63 MB/s throughput**. SSZ is
fundamentally structured-memcpy + bitfield-set; 300-500 MB/s is reasonable
to target. The 5-8× gap suggests something inefficient in the SSZ-Zig
crate's encode loop — likely bounds-checked field writes or non-fastpath
fixed-list handling.

### Suggested investigation

1. Profile `ssz_block_encode` (`zig build bench-forkchoice-ssz` and
   `scripts/profile.sh forkchoice-ssz`). Identify the per-field loop hotspot.
2. Compare against the read-only `ssz_block_decode` at 1.2 µs (50× faster
   than encode for the same shape) — that's so fast it's likely zero-copy
   borrow; encode might be unnecessarily allocating per field.

Expected effect: `ssz_block_encode` 42 µs → 10-15 µs.

---

## Bottleneck #5: XMSS verify — algorithmic floor

Single verify at **~500-650 µs** (NEON / AVX2) is already saturating the
NEON-Poseidon1 inner loop with 10 rayon workers. The "13% wait" per worker
is rayon phase-sync overhead, not zeam's to fix.

### What zeam can do: cache verified pubkeys

`pkgs/xmss/src/lib.zig:PublicKeyCache` exists and is wired into
`verifySignatures`. We have not measured cache hit rate under devnet load.
If hit rate is high (likely — same validator set per epoch), the
*deserialization* cost (SSZ-bytes → `HashSigPublicKey` handle, called by
each `verifySignatures`) is amortized. If hit rate is low, every block's
attestation processing pays the deserialize cost on top of the verify cost.

### Suggested investigation

Add a metric `lean_xmss_pubkey_cache_hits_total` / `misses_total` to
`PublicKeyCache.getOrPut`. Scrape during a devnet run. If hits/(hits+misses)
< 0.95, the cache isn't doing its job and there's a quick fix.

---

## Unknowns (requires devnet capture — Phase 3 of perf-devnet-profile)

These are NOT bottlenecks we can quantify yet. The `slot_probe`
infrastructure on `chain.zig`/`forkchoice.zig` is in place but only fires
under real load.

| Unknown | What probe answers it |
|---|---|
| Are `chain.onBlock` / `produceBlock` exceeding budget under real gossip load? | `chain.onBlock`, `chain.produceBlock` probe over-budget rate |
| Is `fc.aggregate` killing slot timing in steady-state? | `fc.aggregate` probe rate (we already know 3.9 s recursive aggregation can't fit; the question is how often it's exercised) |
| Is libxev IO thread running CPU work it shouldn't (`#803` invariant)? | `flamegraph.svg` filtered to the libxev TID, looking for `apply_raw_block`/`verifySsz`/`aggregate` |
| Is the chain-worker queue saturating? | `lean_chain_queue_depth{queue=block,attestation}` and `lean_chain_queue_dropped_total` from prometheus |
| Top lock contention sites? | flamegraph callers of `pthread_mutex_lock`/`__psynch_cvwait`/`_pthread_cond_wait` |

Capturing these requires running `lean-quickstart` + `scripts/devnet-profile/capture.sh`. The runbook is in `docs/perf/devnet/README.md`; tooling was validated end-to-end on a GitHub Codespace 2026-05-13.

---

## Action ranking by ROI

| # | Action | Expected win | Effort | Where |
|---|---|---:|---|---|
| 1 | Run Phase 3 (devnet capture) to surface the actual runtime bottlenecks | informational; rationalizes the rest | half-day | this branch's tooling |
| 2 | STF subtree hash cache | 5× on STF (150 µs → 30 µs) | days | `pkgs/state-transition/`, `pkgs/types/src/StateHashCache.zig` |
| 3 | Forkchoice hash-map pre-size + arena | 1.5-2× on forkchoice | days | `pkgs/node/src/forkchoice.zig` |
| 4 | SSZ encode hot-path tightening | 3-4× on SSZ encode | days | `ssz.zig` upstream OR locally vendored |
| 5 | XMSS pubkey cache hit-rate metric | informational; gates #6 | hours | `pkgs/xmss/src/lib.zig`, `pkgs/metrics/` |
| 6 | (conditional on #5) XMSS pubkey cache reuse fix | 10-30% on `verifySignatures` if cache is failing | days | wherever cache is invalidated |
| ⊥ | Aggregation speedup | none of consequence in zeam | — | leanMultisig / Plonky3 |

Items 2-4 are all zeam-side, well-scoped, and would each be reasonable
follow-up PRs. Item 1 is the highest-information action — until we have
real-load probe data, items 2-4 are well-founded but their relative
priority is guesswork.

---

## Cross-platform validation note (added 2026-05-13)

The Linux codespace validation (`9a76c3c` `perf-devnet-profile`) re-recorded
`bench-xmss` and `bench-aggregation` symbols via `perf record --call-graph fp`
on a fresh x86_64 codespace. Top frames:

- `p3_monty_31::x86_64_avx2::poseidon1::Poseidon1InternalLayer::permute_state`
- `keccak::keccak_p`
- `p3_mds::karatsuba_convolution::{negacyclic_conv8, conv8}` (AVX2)
- `Poseidon1ExternalLayer::permute_state_{initial, terminal}` (AVX2)

These are the exact analogues of the macOS NEON top frames. The bottleneck
profile is **architecture-independent**: same Plonky3 + leansig hot path,
just compiled to a different vector ISA. No further x86_64-specific tuning
is going to materially shift this.
