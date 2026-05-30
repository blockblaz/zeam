//! Unified FFI shim for the Zig side.
//!
//! Each feature below corresponds to a per-prover glue rlib. The explicit
//! `extern crate` binding forces Cargo/rustc to link the dependency into this
//! `staticlib` even though no Rust-level item from it is referenced here —
//! the only things we care about are the `#[no_mangle] pub extern "C"`
//! functions defined in those crates, which rustc preserves in the final
//! archive as long as the rlib is part of the link set.

// Route every Rust allocation in the process — the prover (rayon witnesses),
// the libp2p networking stack, hashsig — through jemalloc. It releases freed
// memory back to the OS far more readily than the system allocator and
// fragments less under the prover's large, bursty allocations, which is the
// dominant source of node RSS. This is the only staticlib in the link set, so
// the global allocator declared here governs the whole process's Rust side.
//
// The openvm/risc0 zkVM backends ship their own #[global_allocator]
// (e.g. openvm_stark_backend), and only one is allowed per binary — so jemalloc
// is installed only when neither zkVM prover is built. The multisig (devnet5)
// and default builds, which carry the heavy prover, always get it.
#[cfg(not(any(feature = "openvm", feature = "risc0")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "libp2p")]
extern crate libp2p_glue;

#[cfg(feature = "hashsig")]
extern crate hashsig_glue;

#[cfg(feature = "multisig")]
extern crate multisig_glue;

#[cfg(feature = "risc0")]
extern crate risc0_glue;

#[cfg(feature = "openvm")]
extern crate openvm_glue;
