use rec_aggregation::xmss_aggregate::{
    config::{LeanSigPubKey, LeanSigSignature},
    xmss_aggregate_signatures, xmss_setup_aggregation_program, xmss_verify_aggregated_signatures,
    Devnet2XmssAggregateSignature,
};
use ssz::{Decode, Encode};
use std::slice;
use std::sync::Once;

// Import the same leansig types that hashsig-glue uses
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use leansig::signature::SignatureScheme;

type HashSigScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;
type HashSigPublicKey = <HashSigScheme as SignatureScheme>::PublicKey;
type HashSigSignature = <HashSigScheme as SignatureScheme>::Signature;

// Static Once guards for idempotent initialization
// Avoids redundant heavy computation on repeated calls
static PROVER_INIT: Once = Once::new();
static VERIFIER_INIT: Once = Once::new();

// Mirror hashsig-glue's struct layout with #[repr(C)]
// These must match hashsig-glue/src/lib.rs exactly
#[repr(C)]
pub struct PublicKey {
    pub inner: HashSigPublicKey,
}

#[repr(C)]
pub struct Signature {
    pub inner: HashSigSignature,
}

/// Serialize a Devnet2XmssAggregateSignature to SSZ-encoded bytes.
pub fn to_ssz_bytes(agg_sig: &Devnet2XmssAggregateSignature) -> Vec<u8> {
    agg_sig.as_ssz_bytes()
}

/// Deserialize a Devnet2XmssAggregateSignature from SSZ-encoded bytes.
pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Devnet2XmssAggregateSignature, ssz::DecodeError> {
    Devnet2XmssAggregateSignature::from_ssz_bytes(bytes)
}

/// Initialize the prover (idempotent - only runs once)
/// This is safe to call multiple times; heavy computation only happens on first call.
#[no_mangle]
pub extern "C" fn xmss_setup_prover() {
    PROVER_INIT.call_once(|| {
        xmss_setup_aggregation_program();
        whir_p3::precompute_dft_twiddles::<p3_koala_bear::KoalaBear>(1 << 24);
    });
}

/// Initialize the verifier (idempotent - only runs once)
/// This is safe to call multiple times; setup only happens on first call.
#[no_mangle]
pub extern "C" fn xmss_setup_verifier() {
    VERIFIER_INIT.call_once(|| {
        xmss_setup_aggregation_program();
    });
}

/// Aggregate signatures from hashsig-glue handles
/// Returns pointer to Devnet2XmssAggregateSignature on success, null on error
///
/// # Safety
/// - `public_keys` must point to an array of `num_keys` valid pointers to `PublicKey`.
/// - `signatures` must point to an array of `num_sigs` valid pointers to `Signature`.
/// - Each element pointer in those arrays must be non-null and properly aligned.
/// - `message_hash_ptr` must point to at least 32 bytes.
/// - The returned pointer (if non-null) is heap-allocated and must be freed exactly once
///   via `xmss_free_aggregate_signature`.
#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate(
    public_keys: *const *const PublicKey,
    num_keys: usize,
    signatures: *const *const Signature,
    num_sigs: usize,
    message_hash_ptr: *const u8,
    epoch: u32,
) -> *const Devnet2XmssAggregateSignature {
    if public_keys.is_null() || signatures.is_null() || message_hash_ptr.is_null() {
        return std::ptr::null();
    }

    if num_keys != num_sigs {
        return std::ptr::null();
    }

    let message_hash_slice = slice::from_raw_parts(message_hash_ptr, 32);
    let message_hash: &[u8; 32] = match message_hash_slice.try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Access public keys directly from public key handles
    let pub_key_ptrs = slice::from_raw_parts(public_keys, num_keys);
    let mut pub_keys: Vec<LeanSigPubKey> = Vec::with_capacity(num_keys);

    for &pk_ptr in pub_key_ptrs {
        if pk_ptr.is_null() {
            return std::ptr::null();
        }
        pub_keys.push((*pk_ptr).inner.clone());
    }

    // Access signatures directly from signature handles
    let sig_ptrs = slice::from_raw_parts(signatures, num_sigs);
    let mut lean_signatures: Vec<LeanSigSignature> = Vec::with_capacity(num_sigs);

    for &sig_ptr in sig_ptrs {
        if sig_ptr.is_null() {
            return std::ptr::null();
        }
        let sig = &*sig_ptr;
        // The .inner field IS already a LeanSigSignature (same type!)
        // We can clone it directly
        lean_signatures.push(sig.inner.clone());
    }

    // Aggregate using leanMultisig
    let agg_sig = match xmss_aggregate_signatures(&pub_keys, &lean_signatures, message_hash, epoch)
    {
        Ok(sig) => sig,
        Err(_) => return std::ptr::null(),
    };

    // Return the aggregate signature directly
    Box::into_raw(Box::new(agg_sig))
}

/// Verify aggregated signatures using hashsig-glue keypair handles
/// Takes aggregate signature directly
/// Returns true if valid, false if invalid
///
/// # Safety
/// - `public_keys` must point to an array of `num_keys` valid pointers to `PublicKey`.
/// - Each element pointer must be non-null and properly aligned.
/// - `message_hash_ptr` must point to at least 32 bytes.
/// - `agg_sig` must be a valid pointer previously returned by `xmss_aggregate`
///   and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn xmss_verify_aggregated(
    public_keys: *const *const PublicKey,
    num_keys: usize,
    message_hash_ptr: *const u8,
    agg_sig: *const Devnet2XmssAggregateSignature,
    epoch: u32,
) -> bool {
    if public_keys.is_null() || message_hash_ptr.is_null() || agg_sig.is_null() {
        return false;
    }

    let message_hash_slice = slice::from_raw_parts(message_hash_ptr, 32);
    let message_hash: &[u8; 32] = match message_hash_slice.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };

    // Access public keys directly from keypair handles
    let pub_key_ptrs = slice::from_raw_parts(public_keys, num_keys);
    let mut pub_keys: Vec<LeanSigPubKey> = Vec::with_capacity(num_keys);
    for &pk_ptr in pub_key_ptrs {
        if pk_ptr.is_null() {
            return false;
        }
        pub_keys.push((*pk_ptr).inner.clone());
    }

    // Access aggregate signature directly
    let agg_sig_ref = &*agg_sig;

    xmss_verify_aggregated_signatures(&pub_keys, message_hash, agg_sig_ref, epoch).is_ok()
}

/// Free an aggregate signature allocated by `xmss_aggregate`.
///
/// # Safety
/// `agg_sig` must be either null, or a pointer previously returned by `xmss_aggregate`
/// that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn xmss_free_aggregate_signature(
    agg_sig: *mut Devnet2XmssAggregateSignature,
) {
    if !agg_sig.is_null() {
        // Reconstruct the Box to drop and free it.
        drop(Box::from_raw(agg_sig));
    }
}

/// Serialize an aggregate signature to SSZ-encoded bytes.
/// Returns number of bytes written, or 0 on error.
///
/// # Safety
/// - `agg_sig` must be a valid pointer previously returned by `xmss_aggregate`.
/// - `buffer` must point to a valid buffer of at least `buffer_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_signature_to_bytes(
    agg_sig: *const Devnet2XmssAggregateSignature,
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    if agg_sig.is_null() || buffer.is_null() {
        return 0;
    }

    let agg_sig_ref = &*agg_sig;

    let ssz_bytes = to_ssz_bytes(agg_sig_ref);

    if ssz_bytes.len() > buffer_len {
        return 0;
    }

    let output_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    output_slice[..ssz_bytes.len()].copy_from_slice(&ssz_bytes);
    ssz_bytes.len()
}

/// Deserialize an aggregate signature from SSZ-encoded bytes.
/// Returns pointer to Devnet2XmssAggregateSignature on success, null on error.
///
/// # Safety
/// - `bytes` must point to a valid buffer of at least `bytes_len` bytes.
/// - The returned pointer (if non-null) is heap-allocated and must be freed
///   exactly once via `xmss_free_aggregate_signature`.
#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_signature_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
) -> *mut Devnet2XmssAggregateSignature {
    if bytes.is_null() || bytes_len == 0 {
        return std::ptr::null_mut();
    }

    let input_slice = slice::from_raw_parts(bytes, bytes_len);

    match from_ssz_bytes(input_slice) {
        Ok(agg_sig) => Box::into_raw(Box::new(agg_sig)),
        Err(_) => std::ptr::null_mut(),
    }
}
