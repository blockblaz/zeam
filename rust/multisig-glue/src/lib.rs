use leansig_wrapper::{XmssPublicKey, XmssSignature};
use rec_aggregation::{
    aggregate_single_message_signatures, init_aggregation_bytecode,
    merge_single_message_aggregates, split_multi_message_aggregate_by_message,
    verify_multi_message_aggregate, verify_single_message_aggregate,
    MultiMessageAggregateSignature, SingleMessageAggregateSignature,
};
use std::panic::AssertUnwindSafe;
use std::slice;

// Mirror hashsig-glue's struct layout with #[repr(C)]; these must match it exactly.
#[repr(C)]
pub struct PublicKey {
    pub inner: XmssPublicKey,
}

#[repr(C)]
pub struct Signature {
    pub inner: XmssSignature,
}

const MESSAGE_LEN: usize = 32;

// Cached init results: true = succeeded, false = failed.
// Using OnceLock<bool> instead of Once so we can distinguish "succeeded" from "panicked"
// without poisoning the guard. The closure is called exactly once; subsequent calls return
// the cached result without any computation.
static PROVER_READY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static VERIFIER_READY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Initialize the prover (idempotent - only runs once).
///
/// Returns 0 on success, -1 on failure.
///
/// `init_aggregation_bytecode()` may panic (e.g. when the compiled prover bytecode file is
/// missing — ENOENT). A Rust panic through an `extern "C"` boundary is UB, so we wrap the
/// init body in `catch_unwind` and cache the boolean result in a `OnceLock`. The caller (Zig)
/// checks the return code and surfaces a hard error instead of crashing.
#[no_mangle]
pub extern "C" fn xmss_setup_prover() -> i32 {
    let ready = PROVER_READY.get_or_init(|| {
        std::panic::catch_unwind(|| {
            init_aggregation_bytecode();
            backend::precompute_dft_twiddles::<backend::KoalaBear>(1 << 24);
        })
        .is_ok()
    });
    if *ready {
        0
    } else {
        -1
    }
}

/// Initialize the verifier (idempotent - only runs once).
///
/// Returns 0 on success, -1 on failure. Same panic-safety rationale as `xmss_setup_prover`.
#[no_mangle]
pub extern "C" fn xmss_setup_verifier() -> i32 {
    let ready = VERIFIER_READY.get_or_init(|| {
        std::panic::catch_unwind(|| {
            init_aggregation_bytecode();
        })
        .is_ok()
    });
    if *ready {
        0
    } else {
        -1
    }
}

/// Copy `src` into the caller-supplied output buffer using the 0/-1/-2 protocol.
///
/// - returns `0` on success (and writes `src.len()` bytes into `out_buf`),
/// - returns `-2` if `out_cap` is too small (and sets `*out_written = src.len()` so the
///   caller knows the required size),
/// - returns `-1` on a null-pointer error.
///
/// `*out_written` is always set to the required length when `out_written` is non-null.
///
/// # Safety
/// `out_buf` must be valid for `out_cap` bytes; `out_written` must be a valid `*mut usize`.
unsafe fn write_out(src: &[u8], out_buf: *mut u8, out_cap: usize, out_written: *mut usize) -> i32 {
    if out_written.is_null() {
        return -1;
    }
    *out_written = src.len();
    if src.len() > out_cap {
        return -2;
    }
    if !src.is_empty() {
        if out_buf.is_null() {
            return -1;
        }
        std::ptr::copy_nonoverlapping(src.as_ptr(), out_buf, src.len());
    }
    0
}

/// Collect `count` `XmssPublicKey`s from a flat array of `*const PublicKey` starting at `base`.
/// Returns `None` if any pointer is null.
///
/// # Safety
/// `base[0..count]` must be valid pointers (or the function returns None on the first null).
unsafe fn collect_pubkeys(
    base: *const *const PublicKey,
    count: usize,
) -> Option<Vec<XmssPublicKey>> {
    let mut out = Vec::with_capacity(count);
    let ptrs = slice::from_raw_parts(base, count);
    for &p in ptrs {
        if p.is_null() {
            return None;
        }
        out.push((*p).inner.clone());
    }
    Some(out)
}

/// Aggregate raw XMSS signatures plus previously-aggregated child Type-1 proofs into one
/// Type-1 multi-signature (single message, single slot). Output is the compact no-pubkeys
/// wire form. Returns 0/-1/-2 (see `write_out`).
///
/// # Safety
/// - `raw_pub_keys`/`raw_signatures` are arrays of `num_raw` non-null pointers (when num_raw > 0).
/// - When `num_children > 0`: `child_all_pub_keys` is a flat array of `sum(child_num_keys)` pointers,
///   `child_num_keys`/`child_proof_ptrs`/`child_proof_lens` have `num_children` elements, and each
///   `child_proof_ptrs[i]` points to `child_proof_lens[i]` bytes of a Type-1 no-pubkeys wire blob.
/// - `message_hash_ptr` points to at least 32 bytes. Output triple per `write_out`.
#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_type_1(
    raw_pub_keys: *const *const PublicKey,
    raw_signatures: *const *const Signature,
    num_raw: usize,
    num_children: usize,
    child_all_pub_keys: *const *const PublicKey,
    child_num_keys: *const usize,
    child_proof_ptrs: *const *const u8,
    child_proof_lens: *const usize,
    message_hash_ptr: *const u8,
    slot: u32,
    log_inv_rate: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    if message_hash_ptr.is_null() || out_written.is_null() {
        return -1;
    }
    if num_raw > 0 && (raw_pub_keys.is_null() || raw_signatures.is_null()) {
        return -1;
    }
    if num_children > 0
        && (child_all_pub_keys.is_null()
            || child_num_keys.is_null()
            || child_proof_ptrs.is_null()
            || child_proof_lens.is_null())
    {
        return -1;
    }

    let message: [u8; MESSAGE_LEN] =
        match slice::from_raw_parts(message_hash_ptr, MESSAGE_LEN).try_into() {
            Ok(a) => a,
            Err(_) => return -1,
        };

    // Raw (pubkey, signature) pairs.
    let mut raw_xmss: Vec<(XmssPublicKey, XmssSignature)> = Vec::with_capacity(num_raw);
    if num_raw > 0 {
        let pk_ptrs = slice::from_raw_parts(raw_pub_keys, num_raw);
        let sig_ptrs = slice::from_raw_parts(raw_signatures, num_raw);
        for i in 0..num_raw {
            if pk_ptrs[i].is_null() || sig_ptrs[i].is_null() {
                return -1;
            }
            raw_xmss.push(((*pk_ptrs[i]).inner.clone(), (*sig_ptrs[i]).inner.clone()));
        }
    }

    // Child Type-1 proofs: reconstruct each from (pubkeys, no-pubkeys wire).
    let mut children: Vec<SingleMessageAggregateSignature> = Vec::with_capacity(num_children);
    if num_children > 0 {
        let counts = slice::from_raw_parts(child_num_keys, num_children);
        let proof_ptrs = slice::from_raw_parts(child_proof_ptrs, num_children);
        let proof_lens = slice::from_raw_parts(child_proof_lens, num_children);
        let mut offset = 0usize;
        for i in 0..num_children {
            let n = counts[i];
            let pks = match collect_pubkeys(child_all_pub_keys.add(offset), n) {
                Some(v) => v,
                None => return -1,
            };
            // Guard the flat-array cursor against usize overflow: a wrapped offset would make the
            // next `.add(offset)` compute a wild pointer and read out of bounds.
            offset = match offset.checked_add(n) {
                Some(v) => v,
                None => return -1,
            };
            if proof_ptrs[i].is_null() || proof_lens[i] == 0 {
                return -1;
            }
            let wire = slice::from_raw_parts(proof_ptrs[i], proof_lens[i]);
            match SingleMessageAggregateSignature::decompress_without_pubkeys(wire, pks) {
                Some(t1) => children.push(t1),
                None => return -1,
            }
        }
    }

    // `aggregate_single_message_signatures` contains debug asserts (matching message/slot, size
    // bounds); wrap so a violation returns -1 instead of unwinding across the FFI boundary.
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        aggregate_single_message_signatures(&children, raw_xmss, message, slot, log_inv_rate)
    }));
    let t1 = match result {
        Ok(Ok(t1)) => t1,
        _ => return -1,
    };
    write_out(
        &t1.compress_without_pubkeys(),
        out_buf,
        out_cap,
        out_written,
    )
}

/// Verify a Type-1 multi-signature against a resolved pubkey set, message, and slot.
/// `verify_single_message_aggregate` checks only the SNARK; the (message, slot) binding is enforced
/// here by comparing the decoded proof's bound message/slot to the caller-supplied expected values.
///
/// # Safety
/// - `public_keys` is an array of `num_keys` non-null pointers (when num_keys > 0).
/// - `message_hash_ptr` points to at least 32 bytes; `type_1_bytes` points to `type_1_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn xmss_verify_type_1(
    public_keys: *const *const PublicKey,
    num_keys: usize,
    message_hash_ptr: *const u8,
    slot: u32,
    type_1_bytes: *const u8,
    type_1_len: usize,
) -> bool {
    if message_hash_ptr.is_null() || type_1_bytes.is_null() {
        return false;
    }
    if num_keys > 0 && public_keys.is_null() {
        return false;
    }
    let message: [u8; MESSAGE_LEN] =
        match slice::from_raw_parts(message_hash_ptr, MESSAGE_LEN).try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
    let pks = match collect_pubkeys(public_keys, num_keys) {
        Some(v) => v,
        None => return false,
    };
    let wire = slice::from_raw_parts(type_1_bytes, type_1_len);
    let sig = match SingleMessageAggregateSignature::decompress_without_pubkeys(wire, pks) {
        Some(s) => s,
        None => return false,
    };
    // Message + slot binding: verify_single_message_aggregate only proves the SNARK, not what was signed.
    if sig.info.without_pubkeys.message != message || sig.info.without_pubkeys.slot != slot {
        return false;
    }
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        verify_single_message_aggregate(&sig).is_ok()
    }))
    .unwrap_or(false)
}

/// Merge N Type-1 proofs (each over a distinct message) into one Type-2 multi-message proof.
/// Each part is reconstructed from its (pubkeys, no-pubkeys wire). Output is the Type-2 compact
/// no-pubkeys wire form. Returns 0/-1/-2 (see `write_out`).
///
/// # Safety
/// - `type_1_proof_ptrs`/`type_1_proof_lens` have `num_parts` elements; each ptr points to its len.
/// - `pks_flat` is a flat array of `sum(pks_per_part_counts)` pointers; `pks_per_part_counts` has
///   `num_parts` elements. Output triple per `write_out`.
#[no_mangle]
pub unsafe extern "C" fn xmss_merge_type_1_to_type_2(
    num_parts: usize,
    type_1_proof_ptrs: *const *const u8,
    type_1_proof_lens: *const usize,
    pks_flat: *const *const PublicKey,
    pks_per_part_counts: *const usize,
    log_inv_rate: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    if num_parts == 0 || out_written.is_null() {
        return -1;
    }
    if type_1_proof_ptrs.is_null()
        || type_1_proof_lens.is_null()
        || pks_flat.is_null()
        || pks_per_part_counts.is_null()
    {
        return -1;
    }
    let proof_ptrs = slice::from_raw_parts(type_1_proof_ptrs, num_parts);
    let proof_lens = slice::from_raw_parts(type_1_proof_lens, num_parts);
    let counts = slice::from_raw_parts(pks_per_part_counts, num_parts);
    let mut parts: Vec<SingleMessageAggregateSignature> = Vec::with_capacity(num_parts);
    let mut offset = 0usize;
    for i in 0..num_parts {
        let n = counts[i];
        let pks = match collect_pubkeys(pks_flat.add(offset), n) {
            Some(v) => v,
            None => return -1,
        };
        // Guard the flat-array cursor against usize overflow (see xmss_aggregate_type_1).
        offset = match offset.checked_add(n) {
            Some(v) => v,
            None => return -1,
        };
        if proof_ptrs[i].is_null() || proof_lens[i] == 0 {
            return -1;
        }
        let wire = slice::from_raw_parts(proof_ptrs[i], proof_lens[i]);
        match SingleMessageAggregateSignature::decompress_without_pubkeys(wire, pks) {
            Some(t1) => parts.push(t1),
            None => return -1,
        }
    }
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        merge_single_message_aggregates(parts, log_inv_rate)
    }));
    let t2 = match result {
        Ok(Ok(t2)) => t2,
        _ => return -1,
    };
    write_out(
        &t2.compress_without_pubkeys(),
        out_buf,
        out_cap,
        out_written,
    )
}

/// Recover the Type-1 component bound to `target_message_hash` out of a Type-2 proof.
/// `pks_flat`/`pks_per_message_counts` give the per-component pubkey layout the Type-2 was built
/// with (in component order). Output is the recovered Type-1 compact no-pubkeys wire form.
/// Returns 0/-1/-2 (see `write_out`).
///
/// # Safety
/// - `type_2_bytes` points to `type_2_len` bytes; `target_message_hash` points to >= 32 bytes.
/// - `pks_flat` is a flat array of `sum(pks_per_message_counts)` pointers; `pks_per_message_counts`
///   has `num_messages` elements. Output triple per `write_out`.
#[no_mangle]
pub unsafe extern "C" fn xmss_split_type_2_by_msg(
    type_2_bytes: *const u8,
    type_2_len: usize,
    pks_flat: *const *const PublicKey,
    pks_per_message_counts: *const usize,
    num_messages: usize,
    target_message_hash: *const u8,
    log_inv_rate: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    if type_2_bytes.is_null() || target_message_hash.is_null() || out_written.is_null() {
        return -1;
    }
    if num_messages > 0 && (pks_flat.is_null() || pks_per_message_counts.is_null()) {
        return -1;
    }
    let target: [u8; MESSAGE_LEN] =
        match slice::from_raw_parts(target_message_hash, MESSAGE_LEN).try_into() {
            Ok(a) => a,
            Err(_) => return -1,
        };
    let counts = slice::from_raw_parts(pks_per_message_counts, num_messages);
    let mut per_msg: Vec<Vec<XmssPublicKey>> = Vec::with_capacity(num_messages);
    let mut offset = 0usize;
    for &n in counts {
        let pks = match collect_pubkeys(pks_flat.add(offset), n) {
            Some(v) => v,
            None => return -1,
        };
        // Guard the flat-array cursor against usize overflow (see xmss_aggregate_type_1).
        offset = match offset.checked_add(n) {
            Some(v) => v,
            None => return -1,
        };
        per_msg.push(pks);
    }
    let wire = slice::from_raw_parts(type_2_bytes, type_2_len);
    let type_2 = match MultiMessageAggregateSignature::decompress_without_pubkeys(wire, per_msg) {
        Some(t) => t,
        None => return -1,
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        split_multi_message_aggregate_by_message(type_2, target, log_inv_rate)
    }));
    let t1 = match result {
        Ok(Ok(t1)) => t1,
        _ => return -1,
    };
    write_out(
        &t1.compress_without_pubkeys(),
        out_buf,
        out_cap,
        out_written,
    )
}

/// Verify a Type-2 multi-message proof. `verify_multi_message_aggregate` checks only the SNARK; the per-component
/// (message, slot) binding is enforced here by comparing each decoded component's bound
/// message/slot to the caller-supplied parallel arrays. Without this binding, a proposer could
/// pair honest signatures with attacker-chosen attestation data that resolves to the same pubkeys.
///
/// # Safety
/// - `type_2_bytes` points to `type_2_len` bytes.
/// - `pks_flat` is a flat array of `sum(pks_per_message_counts)` pointers; `pks_per_message_counts`
///   has `num_messages` elements (component order).
/// - `message_hashes` points to `num_messages * 32` bytes; `message_slots` to `num_messages` u32s.
#[no_mangle]
pub unsafe extern "C" fn xmss_verify_type_2(
    type_2_bytes: *const u8,
    type_2_len: usize,
    pks_flat: *const *const PublicKey,
    pks_per_message_counts: *const usize,
    num_messages: usize,
    message_hashes: *const u8,
    message_slots: *const u32,
) -> bool {
    if type_2_bytes.is_null() || message_hashes.is_null() || message_slots.is_null() {
        return false;
    }
    if num_messages == 0 || pks_flat.is_null() || pks_per_message_counts.is_null() {
        return false;
    }
    let counts = slice::from_raw_parts(pks_per_message_counts, num_messages);
    let mut per_msg: Vec<Vec<XmssPublicKey>> = Vec::with_capacity(num_messages);
    let mut offset = 0usize;
    for &n in counts {
        let pks = match collect_pubkeys(pks_flat.add(offset), n) {
            Some(v) => v,
            None => return false,
        };
        // Guard the flat-array cursor against usize overflow (see xmss_aggregate_type_1).
        offset = match offset.checked_add(n) {
            Some(v) => v,
            None => return false,
        };
        per_msg.push(pks);
    }
    let wire = slice::from_raw_parts(type_2_bytes, type_2_len);
    let sig = match MultiMessageAggregateSignature::decompress_without_pubkeys(wire, per_msg) {
        Some(s) => s,
        None => return false,
    };
    // Per-component message + slot binding. decompress already enforced component count match,
    // but re-check defensively before indexing.
    if sig.info.len() != num_messages {
        return false;
    }
    let hashes = slice::from_raw_parts(message_hashes, num_messages * MESSAGE_LEN);
    let slots = slice::from_raw_parts(message_slots, num_messages);
    for i in 0..num_messages {
        let mut expected = [0u8; MESSAGE_LEN];
        expected.copy_from_slice(&hashes[i * MESSAGE_LEN..(i + 1) * MESSAGE_LEN]);
        if sig.info[i].without_pubkeys.message != expected
            || sig.info[i].without_pubkeys.slot != slots[i]
        {
            return false;
        }
    }
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        verify_multi_message_aggregate(&sig).is_ok()
    }))
    .unwrap_or(false)
}

/// Configure the global rayon thread pool used by the XMSS aggregate prover.
///
/// Must be called **before** `xmss_setup_prover` and before any aggregation work begins. The
/// rayon global pool can only be configured once; subsequent calls are silently ignored.
///
/// `num_threads = 0` means "use rayon's default" (one thread per logical CPU). Typical caller:
/// set to `cpu_count - 3` to reserve cores for libxev, the chain worker, and the rust-libp2p
/// network thread.
///
/// Returns 0 on success or if the pool was already initialized, -1 never (errors are treated as ok).
#[no_mangle]
pub extern "C" fn xmss_set_rayon_threads(num_threads: usize) -> i32 {
    match rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
    {
        Ok(()) => 0,
        // ThreadPoolBuildError is returned when the global pool was already
        // initialized — that's fine, treat it as success.
        Err(_) => 0,
    }
}
