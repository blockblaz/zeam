# Profile findings

Append entries as flamegraphs reveal something worth remembering.
Format: ISO date — target — one-line finding — link/path to evidence.

---

2026-05-12 — xmss — 80%+ of CPU time inside hashsig_glue Rust FFI: dominated by p3_monty_31 Poseidon1 (KoalaBear, aarch64-NEON) across 10 rayon worker threads, with keccak::p1600 and leansig::tweak_hash_tree as secondary contributors; no allocator pressure observed (libsystem_malloc absent from hot path)
