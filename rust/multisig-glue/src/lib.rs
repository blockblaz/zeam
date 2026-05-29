use leansig_wrapper::{XmssPublicKey, XmssSignature};
use rayon::prelude::*;
use rec_aggregation::{
    init_aggregation_bytecode, xmss_aggregate as rec_xmss_aggregate, xmss_verify_aggregation,
    AggregatedXMSS,
};
use std::slice;
use std::sync::OnceLock;
use std::time::Instant;

// Mirror hashsig-glue's struct layout with #[repr(C)]
// These must match hashsig-glue/src/lib.rs exactly
#[repr(C)]
pub struct PublicKey {
    pub inner: XmssPublicKey,
}

#[repr(C)]
pub struct Signature {
    pub inner: XmssSignature,
}

/// Initialize XMSS aggregation (both prove and verify state). Returns 0 on success, -1 on panic.
///
/// Idempotent: the underlying init runs at most once per process. Subsequent calls return 0
/// without re-running `init_aggregation_bytecode()` or the DFT-twiddle precompute. This is
/// defensive — the production caller invokes this exactly once at node startup, but tests
/// and refactors are guarded so a second call cannot double-init global state.
///
/// `catch_unwind` is required because a Rust panic through an `extern "C"` boundary is UB —
/// `init_aggregation_bytecode()` panics when the compiled prover bytecode file is missing.
/// A panicking first call leaves the `OnceLock` empty, so a later call can retry.
#[no_mangle]
pub extern "C" fn setup_xmss_aggregation() -> i32 {
    static INIT: OnceLock<()> = OnceLock::new();
    match std::panic::catch_unwind(|| {
        INIT.get_or_init(|| {
            init_aggregation_bytecode();
            backend::precompute_dft_twiddles::<backend::KoalaBear>(1 << 24);
        });
    }) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Aggregate signatures with recursive child proof support.
/// Returns pointer to AggregatedXMSS on success, null on error.
///
/// # Safety
/// - `raw_pub_keys` must point to an array of `num_raw` valid pointers to `PublicKey`.
/// - `raw_signatures` must point to an array of `num_raw` valid pointers to `Signature`.
/// - When `num_children > 0`:
///   - `child_all_pub_keys` must point to a flat array of PublicKey pointers
///     with total length = sum of `child_num_keys[0..num_children]`.
///   - `child_num_keys` must point to an array of `num_children` elements.
///   - `child_proof_ptrs` must point to an array of `num_children` pointers to proof bytes.
///   - `child_proof_lens` must point to an array of `num_children` lengths.
/// - `message_hash_ptr` must point to at least 32 bytes.
/// - The returned pointer (if non-null) is heap-allocated and must be freed exactly once
///   via `xmss_free_aggregate_signature`.
#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate(
    // Raw XMSS signatures
    raw_pub_keys: *const *const PublicKey,
    raw_signatures: *const *const Signature,
    num_raw: usize,
    // Children
    num_children: usize,
    child_all_pub_keys: *const *const PublicKey,
    child_num_keys: *const usize,
    child_proof_ptrs: *const *const u8,
    child_proof_lens: *const usize,
    // Common parameters
    message_hash_ptr: *const u8,
    slot: u32,
    log_inv_rate: usize,
    // Phase timing out-params (#940). Each pointer is optional (null = ignored).
    // On a successful call, the function writes elapsed nanoseconds for each
    // internal phase:
    //   * `out_marshal_ns`  — Rust-side argument deserialize: raw XMSS clones,
    //                         child public-key collection, child proof
    //                         deserialize (the work between FFI entry and the
    //                         `rec_xmss_aggregate` call).
    //   * `out_stark_ns`    — `rec_xmss_aggregate` itself (leanMultisig STARK
    //                         prove). This is the only phase whose cost is
    //                         expected to scale with `num_raw` per lean-bench.
    //   * `out_post_ns`     — `Box::into_raw` of the returned aggregate (no
    //                         work beyond a pointer wrap; instrumented for
    //                         completeness so the three buckets sum to the
    //                         total observed externally on
    //                         `zeam_xmss_rec_aggregate_prove_seconds`).
    // On the early-return error paths the out-pointers are left untouched.
    out_marshal_ns: *mut u64,
    out_stark_ns: *mut u64,
    out_post_ns: *mut u64,
) -> *const AggregatedXMSS {
    if message_hash_ptr.is_null() {
        return std::ptr::null();
    }
    let t_entry = Instant::now();
    if num_raw > 0 && (raw_pub_keys.is_null() || raw_signatures.is_null()) {
        return std::ptr::null();
    }
    if num_children > 0
        && (child_all_pub_keys.is_null()
            || child_num_keys.is_null()
            || child_proof_ptrs.is_null()
            || child_proof_lens.is_null())
    {
        return std::ptr::null();
    }

    let message_hash: &[u8; 32] = match slice::from_raw_parts(message_hash_ptr, 32).try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null(),
    };

    // Build raw XMSS pairs: (XmssPublicKey, XmssSignature)
    let mut raw_xmss: Vec<(XmssPublicKey, XmssSignature)> = Vec::with_capacity(num_raw);
    if num_raw > 0 {
        let pk_ptrs = slice::from_raw_parts(raw_pub_keys, num_raw);
        let sig_ptrs = slice::from_raw_parts(raw_signatures, num_raw);
        for i in 0..num_raw {
            if pk_ptrs[i].is_null() || sig_ptrs[i].is_null() {
                return std::ptr::null();
            }
            raw_xmss.push(((*pk_ptrs[i]).inner.clone(), (*sig_ptrs[i]).inner.clone()));
        }
    }

    // Build children: Vec<(&[XmssPublicKey], AggregatedXMSS)>
    // We need owned pub key vecs and deserialized proofs
    let mut children_pks: Vec<Vec<XmssPublicKey>> = Vec::with_capacity(num_children);
    let mut children_proofs: Vec<AggregatedXMSS> = Vec::with_capacity(num_children);

    if num_children > 0 {
        let num_keys_arr = slice::from_raw_parts(child_num_keys, num_children);
        let proof_ptrs = slice::from_raw_parts(child_proof_ptrs, num_children);
        let proof_lens = slice::from_raw_parts(child_proof_lens, num_children);

        let total_child_pks: usize = num_keys_arr.iter().sum();
        let all_pk_ptrs = slice::from_raw_parts(child_all_pub_keys, total_child_pks);

        let mut pk_offset: usize = 0;
        for i in 0..num_children {
            // Collect pub keys for this child
            let n = num_keys_arr[i];
            let mut pks = Vec::with_capacity(n);
            for j in 0..n {
                let pk_ptr = all_pk_ptrs[pk_offset + j];
                if pk_ptr.is_null() {
                    return std::ptr::null();
                }
                pks.push((*pk_ptr).inner.clone());
            }
            pk_offset += n;
            children_pks.push(pks);

            // Deserialize child proof
            if proof_ptrs[i].is_null() || proof_lens[i] == 0 {
                return std::ptr::null();
            }
            let proof_bytes = slice::from_raw_parts(proof_ptrs[i], proof_lens[i]);
            let proof = match AggregatedXMSS::deserialize(proof_bytes) {
                Some(p) => p,
                None => return std::ptr::null(),
            };
            children_proofs.push(proof);
        }
    }

    // Build children_with_keys: &[(&[XmssPublicKey], AggregatedXMSS)]
    let children_with_keys: Vec<(&[XmssPublicKey], AggregatedXMSS)> = children_pks
        .iter()
        .zip(children_proofs)
        .map(|(pks, proof)| (pks.as_slice(), proof))
        .collect();

    let t_marshal_done = Instant::now();

    // Call rec_aggregation
    let (_pub_keys, agg_sig) = rec_xmss_aggregate(
        &children_with_keys,
        raw_xmss,
        message_hash,
        slot,
        log_inv_rate,
    );

    let t_stark_done = Instant::now();

    let result = Box::into_raw(Box::new(agg_sig));

    let t_post_done = Instant::now();

    // Write phase timings if the caller passed non-null out-pointers.
    if !out_marshal_ns.is_null() {
        *out_marshal_ns = t_marshal_done.duration_since(t_entry).as_nanos() as u64;
    }
    if !out_stark_ns.is_null() {
        *out_stark_ns = t_stark_done.duration_since(t_marshal_done).as_nanos() as u64;
    }
    if !out_post_ns.is_null() {
        *out_post_ns = t_post_done.duration_since(t_stark_done).as_nanos() as u64;
    }

    result
}

/// Verify aggregated signatures.
/// Returns true if valid, false if invalid.
///
/// # Safety
/// - `public_keys` must point to an array of `num_keys` valid pointers to `PublicKey`.
/// - `message_hash_ptr` must point to at least 32 bytes.
/// - `agg_sig_bytes` must point to at least `agg_sig_len` bytes of a serialized AggregatedXMSS.
#[no_mangle]
pub unsafe extern "C" fn xmss_verify_aggregated(
    public_keys: *const *const PublicKey,
    num_keys: usize,
    message_hash_ptr: *const u8,
    agg_sig_bytes: *const u8,
    agg_sig_len: usize,
    slot: u32,
) -> bool {
    if public_keys.is_null() || message_hash_ptr.is_null() || agg_sig_bytes.is_null() {
        return false;
    }

    let message_hash: &[u8; 32] = match slice::from_raw_parts(message_hash_ptr, 32).try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };

    // Deserialize aggregate signature
    let bytes = slice::from_raw_parts(agg_sig_bytes, agg_sig_len);
    let agg_sig = match AggregatedXMSS::deserialize(bytes) {
        Some(sig) => sig,
        None => return false,
    };

    // Collect public keys
    let pub_key_ptrs = slice::from_raw_parts(public_keys, num_keys);
    let mut pub_keys: Vec<XmssPublicKey> = Vec::with_capacity(num_keys);
    for &pk_ptr in pub_key_ptrs {
        if pk_ptr.is_null() {
            return false;
        }
        pub_keys.push((*pk_ptr).inner.clone());
    }

    xmss_verify_aggregation(pub_keys, &agg_sig, message_hash, slot).is_ok()
}

/// Verify multiple aggregated signatures on the configured rayon pool.
/// Returns true only if every task is valid.
///
/// # Safety
/// - `public_key_offsets` and `public_key_counts` must contain `num_tasks` elements.
/// - `public_keys` must contain all task public-key pointers flattened together.
/// - `message_hashes` must contain `num_tasks * 32` bytes.
/// - `agg_sig_ptrs`, `agg_sig_lens`, and `slots` must contain `num_tasks` elements.
#[no_mangle]
pub unsafe extern "C" fn xmss_verify_aggregated_batch(
    public_key_offsets: *const usize,
    public_key_counts: *const usize,
    num_tasks: usize,
    public_keys: *const *const PublicKey,
    message_hashes: *const u8,
    agg_sig_ptrs: *const *const u8,
    agg_sig_lens: *const usize,
    slots: *const u32,
) -> bool {
    if num_tasks == 0 {
        return true;
    }
    if public_key_offsets.is_null()
        || public_key_counts.is_null()
        || public_keys.is_null()
        || message_hashes.is_null()
        || agg_sig_ptrs.is_null()
        || agg_sig_lens.is_null()
        || slots.is_null()
    {
        return false;
    }

    let offsets = slice::from_raw_parts(public_key_offsets, num_tasks);
    let counts = slice::from_raw_parts(public_key_counts, num_tasks);
    let total_keys = match offsets
        .iter()
        .zip(counts.iter())
        .map(|(offset, count)| offset.checked_add(*count))
        .collect::<Option<Vec<usize>>>()
    {
        Some(ends) => ends.into_iter().max().unwrap_or(0),
        None => return false,
    };
    let key_ptrs = slice::from_raw_parts(public_keys, total_keys);
    let hashes = slice::from_raw_parts(message_hashes, num_tasks * 32);
    let sig_ptrs = slice::from_raw_parts(agg_sig_ptrs, num_tasks);
    let sig_lens = slice::from_raw_parts(agg_sig_lens, num_tasks);
    let task_slots = slice::from_raw_parts(slots, num_tasks);

    struct VerifyTask {
        public_keys: Vec<usize>,
        message_hash: [u8; 32],
        sig_ptr: usize,
        sig_len: usize,
        slot: u32,
    }

    let mut tasks: Vec<VerifyTask> = Vec::with_capacity(num_tasks);
    for i in 0..num_tasks {
        let start = offsets[i];
        let end = match start.checked_add(counts[i]) {
            Some(end) if end <= key_ptrs.len() => end,
            _ => return false,
        };
        let message_hash: [u8; 32] = match hashes[i * 32..(i + 1) * 32].try_into() {
            Ok(hash) => hash,
            Err(_) => return false,
        };
        if sig_ptrs[i].is_null() || sig_lens[i] == 0 {
            return false;
        }
        tasks.push(VerifyTask {
            public_keys: key_ptrs[start..end]
                .iter()
                .map(|ptr| *ptr as usize)
                .collect(),
            message_hash,
            sig_ptr: sig_ptrs[i] as usize,
            sig_len: sig_lens[i],
            slot: task_slots[i],
        });
    }

    tasks.par_iter().all(|task| {
        let sig_bytes = slice::from_raw_parts(task.sig_ptr as *const u8, task.sig_len);
        let agg_sig = match AggregatedXMSS::deserialize(sig_bytes) {
            Some(sig) => sig,
            None => return false,
        };

        let mut pub_keys: Vec<XmssPublicKey> = Vec::with_capacity(task.public_keys.len());
        for &pk_ptr in &task.public_keys {
            let pk_ptr = pk_ptr as *const PublicKey;
            if pk_ptr.is_null() {
                return false;
            }
            pub_keys.push((*pk_ptr).inner.clone());
        }

        xmss_verify_aggregation(pub_keys, &agg_sig, &task.message_hash, task.slot).is_ok()
    })
}

/// Serialize an AggregatedXMSS to bytes (postcard + lz4).
/// Returns number of bytes written, or 0 on error.
///
/// # Safety
/// - `agg_sig` must be a valid pointer previously returned by `xmss_aggregate`.
/// - `buffer` must point to a valid buffer of at least `buffer_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_signature_to_bytes(
    agg_sig: *const AggregatedXMSS,
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    if agg_sig.is_null() || buffer.is_null() {
        return 0;
    }

    let agg_sig_ref = &*agg_sig;
    let serialized = agg_sig_ref.serialize();

    if serialized.len() > buffer_len {
        return 0;
    }

    let output_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    output_slice[..serialized.len()].copy_from_slice(&serialized);
    serialized.len()
}

/// Deserialize an AggregatedXMSS from bytes (postcard + lz4).
/// Returns pointer to AggregatedXMSS on success, null on error.
///
/// # Safety
/// - `bytes` must point to a valid buffer of at least `bytes_len` bytes.
/// - The returned pointer (if non-null) is heap-allocated and must be freed
///   exactly once via `xmss_free_aggregate_signature`.
#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_signature_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
) -> *mut AggregatedXMSS {
    if bytes.is_null() || bytes_len == 0 {
        return std::ptr::null_mut();
    }

    let input_slice = slice::from_raw_parts(bytes, bytes_len);

    match AggregatedXMSS::deserialize(input_slice) {
        Some(agg_sig) => Box::into_raw(Box::new(agg_sig)),
        None => std::ptr::null_mut(),
    }
}

/// Free an aggregate signature allocated by `xmss_aggregate` or `xmss_aggregate_signature_from_bytes`.
///
/// # Safety
/// `agg_sig` must be either null, or a pointer previously returned by `xmss_aggregate`
/// or `xmss_aggregate_signature_from_bytes` that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn xmss_free_aggregate_signature(agg_sig: *mut AggregatedXMSS) {
    if !agg_sig.is_null() {
        drop(Box::from_raw(agg_sig));
    }
}

/// Configure the global rayon thread pool used by the XMSS aggregate prover.
///
/// Must be called **before** `setup_xmss_aggregation` and before any aggregation work
/// begins. The rayon global pool can only be configured once; subsequent calls
/// are silently ignored (rayon returns `ThreadPoolBuildError` which we discard).
///
/// `num_threads = 0` means "use rayon's default" (one thread per logical CPU).
/// Typical caller: set to `cpu_count - 3` to reserve cores for libxev, the
/// chain worker, and the rust-libp2p network thread (issue #873 comment).
///
/// Returns 0 on success or if the pool was already initialized, -1 on build error.
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
