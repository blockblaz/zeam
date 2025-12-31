use lean_multisig::{
    xmss_aggregate_signatures, xmss_aggregation_setup_prover, xmss_aggregation_setup_verifier,
    xmss_generate_phony_signatures as lm_xmss_generate_phony_signatures,
    xmss_verify_aggregated_signatures, XmssPublicKey, XmssSignature, F, XMSS_MAX_LOG_LIFETIME,
    XMSS_MIN_LOG_LIFETIME,
};
use std::slice;
use xmss::WotsSignature;

#[repr(C)]
pub struct CXmssPublicKey {
    merkle_root: [u32; 8],
    first_slot: u64,
    log_lifetime: usize,
}

#[repr(C)]
pub struct CWotsSignature {
    chain_tips: [[u32; 8]; 66],
    randomness: [u32; 8],
}

#[repr(C)]
pub struct CXmssSignature {
    wots_signature: CWotsSignature,
    slot: u64,
    merkle_proof_ptr: *const u32,
    merkle_proof_len: usize,
}

unsafe fn u32_to_field(v: u32) -> F {
    std::mem::transmute(v)
}

#[allow(dead_code)]
unsafe fn field_to_u32(f: F) -> u32 {
    std::mem::transmute(f)
}

unsafe fn convert_pubkey(c_pk: &CXmssPublicKey) -> XmssPublicKey {
    XmssPublicKey {
        merkle_root: std::array::from_fn(|i| u32_to_field(c_pk.merkle_root[i])),
        first_slot: c_pk.first_slot,
        log_lifetime: c_pk.log_lifetime,
    }
}

unsafe fn convert_signature(c_sig: &CXmssSignature) -> XmssSignature {
    let chain_tips: [[F; 8]; 66] = std::array::from_fn(|i| {
        std::array::from_fn(|j| u32_to_field(c_sig.wots_signature.chain_tips[i][j]))
    });

    let randomness: [F; 8] =
        std::array::from_fn(|i| u32_to_field(c_sig.wots_signature.randomness[i]));

    let merkle_proof_u32 =
        slice::from_raw_parts(c_sig.merkle_proof_ptr, c_sig.merkle_proof_len * 8);

    let merkle_proof: Vec<[F; 8]> = merkle_proof_u32
        .chunks_exact(8)
        .map(|chunk| std::array::from_fn(|i| u32_to_field(chunk[i])))
        .collect();

    XmssSignature {
        wots_signature: WotsSignature {
            chain_tips,
            randomness,
        },
        slot: c_sig.slot,
        merkle_proof,
    }
}

/// Generate phony XMSS signatures and C-friendly structures for tests
/// Returns 0 on success, -1 on error
/// # Safety
/// This is meant to be called from zig, so the pointers will always dereference correctly
#[no_mangle]
pub unsafe extern "C" fn xmss_generate_phony_signatures(
    log_lifetimes_ptr: *const usize,
    log_lifetimes_len: usize,
    message_hash_ptr: *const u32,
    slot: u64,
    out_pub_keys_ptr: *mut CXmssPublicKey,
    out_pub_keys_len: usize,
    out_signatures_ptr: *mut CXmssSignature,
    out_signatures_len: usize,
    out_merkle_buf_ptr: *mut u32,
    out_merkle_buf_len: usize,
) -> i32 {
    if log_lifetimes_ptr.is_null()
        || message_hash_ptr.is_null()
        || out_pub_keys_ptr.is_null()
        || out_signatures_ptr.is_null()
        || out_merkle_buf_ptr.is_null()
    {
        return -1;
    }

    if out_pub_keys_len != log_lifetimes_len || out_signatures_len != log_lifetimes_len {
        return -1;
    }

    unsafe {
        let log_lifetimes = slice::from_raw_parts(log_lifetimes_ptr, log_lifetimes_len);
        if log_lifetimes
            .iter()
            .any(|&ll| !(XMSS_MIN_LOG_LIFETIME..=XMSS_MAX_LOG_LIFETIME).contains(&ll))
        {
            return -1;
        }

        let message_hash_u32 = slice::from_raw_parts(message_hash_ptr, 8);
        let message_hash: [F; 8] = std::array::from_fn(|i| u32_to_field(message_hash_u32[i]));

        let required_merkle_words: usize = log_lifetimes.iter().map(|ll| ll * 8).sum();
        if out_merkle_buf_len < required_merkle_words {
            return -1;
        }

        let (pub_keys, signatures) =
            lm_xmss_generate_phony_signatures(log_lifetimes, message_hash, slot);

        let out_pub_keys = slice::from_raw_parts_mut(out_pub_keys_ptr, out_pub_keys_len);
        let out_signatures = slice::from_raw_parts_mut(out_signatures_ptr, out_signatures_len);
        let merkle_buf = slice::from_raw_parts_mut(out_merkle_buf_ptr, out_merkle_buf_len);

        let mut merkle_offset = 0usize;
        for i in 0..log_lifetimes_len {
            let pk = &pub_keys[i];
            out_pub_keys[i] = CXmssPublicKey {
                merkle_root: std::array::from_fn(|j| field_to_u32(pk.merkle_root[j])),
                first_slot: pk.first_slot,
                log_lifetime: pk.log_lifetime,
            };

            let sig = &signatures[i];
            let chain_tips: [[u32; 8]; 66] = std::array::from_fn(|r| {
                std::array::from_fn(|c| field_to_u32(sig.wots_signature.chain_tips[r][c]))
            });
            let randomness: [u32; 8] =
                std::array::from_fn(|j| field_to_u32(sig.wots_signature.randomness[j]));

            let proof_len = sig.merkle_proof.len();
            let proof_words = proof_len * 8;
            for (proof_idx, digest) in sig.merkle_proof.iter().enumerate() {
                for j in 0..8 {
                    merkle_buf[merkle_offset + proof_idx * 8 + j] = field_to_u32(digest[j]);
                }
            }

            out_signatures[i] = CXmssSignature {
                wots_signature: CWotsSignature {
                    chain_tips,
                    randomness,
                },
                slot: sig.slot,
                merkle_proof_ptr: merkle_buf[merkle_offset..].as_ptr(),
                merkle_proof_len: proof_len,
            };

            merkle_offset += proof_words;
        }

        0
    }
}

#[no_mangle]
pub extern "C" fn xmss_setup_prover() {
    xmss_aggregation_setup_prover();
}

#[no_mangle]
pub extern "C" fn xmss_setup_verifier() {
    xmss_aggregation_setup_verifier();
}

/// Aggregate XMSS signatures into a proof
/// Returns 0 on success, -1 on error
/// # Safety
/// This is meant to be called from zig, so the pointers will always dereference correctly
#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate(
    pub_keys_ptr: *const CXmssPublicKey,
    pub_keys_len: usize,
    signatures_ptr: *const CXmssSignature,
    signatures_len: usize,
    message_hash_ptr: *const u32,
    slot: u64,
    out_proof_ptr: *mut u8,
    out_proof_capacity: usize,
    out_proof_len: *mut usize,
) -> i32 {
    if pub_keys_ptr.is_null()
        || signatures_ptr.is_null()
        || message_hash_ptr.is_null()
        || out_proof_ptr.is_null()
        || out_proof_len.is_null()
    {
        return -1;
    }

    unsafe {
        let c_pub_keys = slice::from_raw_parts(pub_keys_ptr, pub_keys_len);
        let c_signatures = slice::from_raw_parts(signatures_ptr, signatures_len);
        let message_hash_u32 = slice::from_raw_parts(message_hash_ptr, 8);

        let pub_keys: Vec<XmssPublicKey> = c_pub_keys.iter().map(|pk| convert_pubkey(pk)).collect();

        let signatures: Vec<XmssSignature> = c_signatures
            .iter()
            .map(|sig| convert_signature(sig))
            .collect();

        let message_hash: [F; 8] = std::array::from_fn(|i| u32_to_field(message_hash_u32[i]));

        let proof = match xmss_aggregate_signatures(&pub_keys, &signatures, message_hash, slot) {
            Ok(p) => p,
            Err(_) => return -1,
        };

        if proof.len() > out_proof_capacity {
            return -1;
        }

        let out_slice = slice::from_raw_parts_mut(out_proof_ptr, out_proof_capacity);
        out_slice[..proof.len()].copy_from_slice(&proof);
        *out_proof_len = proof.len();

        0
    }
}

/// Verify aggregated XMSS signatures
/// Returns 1 if valid, 0 if invalid, -1 on error
/// # Safety
/// This is meant to be called from zig, so the pointers will always dereference correctly
#[no_mangle]
pub unsafe extern "C" fn xmss_verify_aggregated(
    pub_keys_ptr: *const CXmssPublicKey,
    pub_keys_len: usize,
    message_hash_ptr: *const u32,
    proof_ptr: *const u8,
    proof_len: usize,
    slot: u64,
) -> i32 {
    if pub_keys_ptr.is_null() || message_hash_ptr.is_null() || proof_ptr.is_null() {
        return -1;
    }

    unsafe {
        let c_pub_keys = slice::from_raw_parts(pub_keys_ptr, pub_keys_len);
        let message_hash_u32 = slice::from_raw_parts(message_hash_ptr, 8);
        let proof_bytes = slice::from_raw_parts(proof_ptr, proof_len);

        let pub_keys: Vec<XmssPublicKey> = c_pub_keys.iter().map(|pk| convert_pubkey(pk)).collect();

        let message_hash: [F; 8] = std::array::from_fn(|i| u32_to_field(message_hash_u32[i]));

        match xmss_verify_aggregated_signatures(&pub_keys, message_hash, proof_bytes, slot) {
            Ok(_) => 1,
            Err(_) => 0,
        }
    }
}
