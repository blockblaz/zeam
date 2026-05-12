# Profile findings

Append entries as flamegraphs reveal something worth remembering.
Format: ISO date — target — one-line finding — link/path to evidence.

---

2026-05-12 — xmss — 80%+ of CPU time inside hashsig_glue Rust FFI: dominated by p3_monty_31 Poseidon1 (KoalaBear, aarch64-NEON) across 10 rayon worker threads, with keccak::p1600 and leansig::tweak_hash_tree as secondary contributors; no allocator pressure observed (libsystem_malloc absent from hot path)

2026-05-12 — stf — profile too sparse (19 samples, ~10ms total runtime) and symbols stripped (ReleaseFast); benchmark shows apply_transition (avg 102µs) faster than apply_raw_block (avg 151µs) because validateResult=false skips hash_tree_root in apply_transition, confirming hash_tree_root is the dominant STF cost when signature verification is excluded

2026-05-12 — aggregation — proof_aggregate_only (8 signers, LOG_INV_RATE_PROD=2): avg 655ms/call; proof_aggregate_with_2_children (2×4-signer child proofs): avg 3.9s/call; profile shows 10 rayon worker threads dominating with ~43k samples each (vs 7k on main thread), symbols stripped in ReleaseFast so leaf frames appear as raw addresses — same pattern as xmss bench; the 6× slowdown for recursive aggregation vs raw aggregation reflects the additional ZK proof composition cost

NOTE — dropped variants: extend_greedy_small and extend_greedy_large are infeasible without refactoring (the greedy logic is inlined inside computeAggregatedSignatures in block.zig:468, not a standalone function); compute_aggregated_signatures deferred (needs Validators + SignaturesMap fixture setup, out of single-task scope)

2026-05-12 — forkchoice-ssz — fc_onBlock avg 82µs, fc_onAttestation avg 98µs (both include ForkChoice re-init per iteration); ssz_block_encode avg 42µs for 2636-byte SignedBlock, ssz_block_decode avg 1.2µs (fast due to ReleaseFast zero-copy); ssz_state_encode avg 26µs for 678-byte BeamState, ssz_state_decode avg 11µs; samply profile (15.8 MB JSON) shows no Rust FFI hot path — workload is pure Zig hashmap/allocator ops (protoArray index insert, AutoHashMap attestation tracker put) and SSZ memcpy/bitfield operations, confirming forkchoice overhead is allocator-bound not crypto-bound

NOTE — deferred variants: fc_acceptNewAttestations requires prior onAttestation state buildup across multiple validator slots — needs a fixture-loading dance beyond single-task scope; hash_tree_root_cached_miss / cached_hit deferred because the centralised cache (slice e) lacks a clean force-miss entry point and the STF bench already measures hash_tree_root cost indirectly via apply_raw_block vs apply_transition contrast

2026-05-12 — aggregation (symbolized re-record, RUSTFLAGS=-Cdebuginfo=line-tables-only -Cstrip=none) — full breakdown per worker thread, 71k samples in bench-aggregation: Poseidon1 internal/partial layer 30%, MDS karatsuba convolution 22%, Poseidon1 external/full layer 14%, Poseidon1Compress top-level wrapper 12%, Keccak p1600 (Shake-PRF) 7%, sumcheck+eval_multilinear 4%, quintic-extension field mul 3%, ShakePRF wrapper 2%, other 6%. Combined Poseidon-related = 78%. Conclusion: aggregation cost lives entirely inside Plonky3+leansig FFI; no zeam-side optimization can move it. Real levers are all upstream: Poseidon1→Poseidon2 (~2× per Plonky3 docs), FFT-based MDS convolution, GPU prover backend. Within zeam, the only meaningful change is *scheduling* — start aggregation 1 slot early (hides latency, doesn't reduce wall-clock).
