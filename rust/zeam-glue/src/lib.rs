//! Unified FFI shim for the Zig side.
//!
//! Each feature below corresponds to a per-prover glue rlib. The explicit
//! `extern crate` binding forces Cargo/rustc to link the dependency into this
//! `staticlib` even though no Rust-level item from it is referenced here —
//! the only things we care about are the `#[no_mangle] pub extern "C"`
//! functions defined in those crates, which rustc preserves in the final
//! archive as long as the rlib is part of the link set.
//!
//! See blockblaz/zeam#773 for the motivation.

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
