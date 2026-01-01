pub const CXmssPublicKey = extern struct {
    merkle_root: [8]u32,
    first_slot: u64,
    log_lifetime: usize,
};

pub const CWotsSignature = extern struct {
    chain_tips: [66][8]u32,
    randomness: [8]u32,
};

pub const CXmssSignature = extern struct {
    wots_signature: CWotsSignature,
    slot: u64,
    merkle_proof_ptr: [*]const u32,
    merkle_proof_len: usize,
};

extern fn xmss_setup_prover() void;
extern fn xmss_setup_verifier() void;
extern fn xmss_aggregate(
    pub_keys_ptr: [*]const CXmssPublicKey,
    pub_keys_len: usize,
    signatures_ptr: [*]const CXmssSignature,
    signatures_len: usize,
    message_hash_ptr: [*]const u32,
    slot: u64,
    out_proof_ptr: [*]u8,
    out_proof_capacity: usize,
    out_proof_len: *usize,
) i32;

extern fn xmss_verify_aggregated(
    pub_keys_ptr: [*]const CXmssPublicKey,
    pub_keys_len: usize,
    message_hash_ptr: [*]const u32,
    proof_ptr: [*]const u8,
    proof_len: usize,
    slot: u64,
) i32;

extern fn xmss_generate_phony_signatures(
    log_lifetimes_ptr: [*]const usize,
    log_lifetimes_len: usize,
    message_hash_ptr: [*]const u32,
    slot: u64,
    out_pub_keys_ptr: [*]CXmssPublicKey,
    out_pub_keys_len: usize,
    out_signatures_ptr: [*]CXmssSignature,
    out_signatures_len: usize,
    out_merkle_buf_ptr: [*]u32,
    out_merkle_buf_len: usize,
) i32;

pub const AggregationError = error{
    GenerationFailed,
    AggregationFailed,
    InvalidSignature,
    VerificationFailed,
};

pub fn setupProver() void {
    xmss_setup_prover();
}

pub fn setupVerifier() void {
    xmss_setup_verifier();
}

pub fn generatePhonySignatures(
    log_lifetimes: []const usize,
    message_hash: *const [8]u32,
    slot: u64,
    pub_keys: []CXmssPublicKey,
    signatures: []CXmssSignature,
    merkle_buf: []u32,
) AggregationError!void {
    const result = xmss_generate_phony_signatures(
        log_lifetimes.ptr,
        log_lifetimes.len,
        message_hash,
        slot,
        pub_keys.ptr,
        pub_keys.len,
        signatures.ptr,
        signatures.len,
        merkle_buf.ptr,
        merkle_buf.len,
    );
    if (result != 0) return AggregationError.GenerationFailed;
}

pub fn aggregate(
    pub_keys: []const CXmssPublicKey,
    signatures: []const CXmssSignature,
    message_hash: *const [8]u32,
    slot: u64,
    proof_buf: []u8,
    out_proof_len: *usize,
) AggregationError!void {
    const result = xmss_aggregate(
        pub_keys.ptr,
        pub_keys.len,
        signatures.ptr,
        signatures.len,
        message_hash,
        slot,
        proof_buf.ptr,
        proof_buf.len,
        out_proof_len,
    );
    if (result != 0) return AggregationError.AggregationFailed;
}

pub fn verifyAggregated(
    pub_keys: []const CXmssPublicKey,
    message_hash: *const [8]u32,
    proof: []const u8,
    slot: u64,
) AggregationError!void {
    const result = xmss_verify_aggregated(
        pub_keys.ptr,
        pub_keys.len,
        message_hash,
        proof.ptr,
        proof.len,
        slot,
    );
    switch (result) {
        1 => {},
        0 => return AggregationError.InvalidSignature,
        -1 => return AggregationError.VerificationFailed,
        else => return AggregationError.VerificationFailed,
    }
}
