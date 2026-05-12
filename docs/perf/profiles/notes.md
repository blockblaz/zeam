# Profile findings

Append entries as flamegraphs reveal something worth remembering.
Format: ISO date — target — one-line finding — link/path to evidence.

---

2026-05-12 — xmss — 80%+ of CPU time inside hashsig_glue Rust FFI: dominated by p3_monty_31 Poseidon1 (KoalaBear, aarch64-NEON) across 10 rayon worker threads, with keccak::p1600 and leansig::tweak_hash_tree as secondary contributors; no allocator pressure observed (libsystem_malloc absent from hot path)

2026-05-12 — stf — profile too sparse (19 samples, ~10ms total runtime) and symbols stripped (ReleaseFast); benchmark shows apply_transition (avg 102µs) faster than apply_raw_block (avg 151µs) because validateResult=false skips hash_tree_root in apply_transition, confirming hash_tree_root is the dominant STF cost when signature verification is excluded
