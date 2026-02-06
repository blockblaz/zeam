const std = @import("std");
const json = std.json;
const types = @import("@zeam/types");
const utils = types.utils;

const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");
const xmss = @import("@zeam/xmss");
const zeam_metrics = @import("@zeam/metrics");

const Allocator = std.mem.Allocator;
const debugLog = zeam_utils.zeamLog;
const StateTransitionError = types.StateTransitionError;

// put the active logs at debug level for now by default
pub const StateTransitionOpts = struct {
    // signatures are validated outside for keeping life simple for the STF prover
    // we will trust client will validate them however the flag here
    // represents such dependency and assumption for STF
    validSignatures: bool = true,
    validateResult: bool = true,
    logger: zeam_utils.ModuleLogger,
};

// pub fn process_epoch(state: types.BeamState) void {
//     // right now nothing to do
//     _ = state;
//     return;
// }

// not active in PQ devnet0 - zig will automatically prune this from code
fn process_execution_payload_header(state: *types.BeamState, block: types.BeamBlock) !void {
    const expected_timestamp = state.genesis_time + block.slot * params.SECONDS_PER_SLOT;
    if (expected_timestamp != block.body.execution_payload_header.timestamp) {
        return StateTransitionError.InvalidExecutionPayloadHeaderTimestamp;
    }
}

pub fn apply_raw_block(allocator: Allocator, state: *types.BeamState, block: *types.BeamBlock, logger: zeam_utils.ModuleLogger) !void {
    // prepare pre state to process block for that slot, may be rename prepare_pre_stateCollapse comment
    const transition_timer = zeam_metrics.lean_state_transition_time_seconds.start();
    defer _ = transition_timer.observe();

    // prepare pre state to process block for that slot, may be rename prepare_pre_state
    try state.process_slots(allocator, block.slot, logger);

    // process block and modify the pre state to post state
    try state.process_block(allocator, block.*, logger);

    logger.debug("extracting state root\n", .{});
    // extract the post state root
    var state_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(*types.BeamState, state, &state_root, allocator);
    block.state_root = state_root;
}

// Verify aggregated signatures using AggregatedSignatureProof
// If pubkey_cache is provided, public keys are cached to avoid repeated SSZ deserialization.
// This can significantly reduce CPU overhead when processing many blocks.
pub fn verifySignatures(
    allocator: Allocator,
    state: *const types.BeamState,
    signed_block: *const types.SignedBlockWithAttestation,
    pubkey_cache: ?*xmss.PublicKeyCache,
) !void {
    const attestations = signed_block.message.block.body.attestations.constSlice();
    const signature_proofs = signed_block.signature.attestation_signatures.constSlice();

    if (attestations.len != signature_proofs.len) {
        return StateTransitionError.InvalidBlockSignatures;
    }

    const validators = state.validators.constSlice();

    for (attestations, signature_proofs) |aggregated_attestation, signature_proof| {
        // Get validator indices from the attestation's aggregation bits
        var validator_indices = try types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, allocator);
        defer validator_indices.deinit(allocator);

        // Get validator indices from the signature proof's participants
        var participant_indices = try types.aggregationBitsToValidatorIndices(&signature_proof.participants, allocator);
        defer participant_indices.deinit(allocator);

        // Verify that the participants EXACTLY match the attestation aggregation bits.
        if (validator_indices.items.len != participant_indices.items.len) {
            return StateTransitionError.InvalidBlockSignatures;
        }
        for (validator_indices.items, participant_indices.items) |att_idx, proof_idx| {
            if (att_idx != proof_idx) {
                return StateTransitionError.InvalidBlockSignatures;
            }
        }

        // Convert validator pubkey bytes to HashSigPublicKey handles
        var public_keys: std.ArrayList(*const xmss.HashSigPublicKey) = .empty;
        try public_keys.ensureTotalCapacity(allocator, validator_indices.items.len);
        defer public_keys.deinit(allocator);

        // Store the PublicKey wrappers so we can free the Rust handles after verification
        // Only used when cache is not provided
        var pubkey_wrappers: std.ArrayList(xmss.PublicKey) = .empty;
        try pubkey_wrappers.ensureTotalCapacity(allocator, validator_indices.items.len);
        defer {
            // Only free wrappers if we're not using a cache
            // When using cache, the cache owns the handles
            if (pubkey_cache == null) {
                for (pubkey_wrappers.items) |*wrapper| {
                    wrapper.deinit();
                }
            }
            pubkey_wrappers.deinit(allocator);
        }

        for (validator_indices.items) |validator_index| {
            if (validator_index >= validators.len) {
                return StateTransitionError.InvalidValidatorId;
            }
            const validator = &validators[validator_index];
            const pubkey_bytes = validator.getPubkey();

            if (pubkey_cache) |cache| {
                // Use cached public key (deserialize on first access, reuse on subsequent)
                const pk_handle = cache.getOrPut(validator_index, pubkey_bytes) catch {
                    return StateTransitionError.InvalidBlockSignatures;
                };
                try public_keys.append(allocator, pk_handle);
            } else {
                // No cache - deserialize each time (legacy behavior)
                const pubkey = xmss.PublicKey.fromBytes(pubkey_bytes) catch {
                    return StateTransitionError.InvalidBlockSignatures;
                };
                try public_keys.append(allocator, pubkey.handle);
                try pubkey_wrappers.append(allocator, pubkey);
            }
        }

        // Compute message hash from attestation data
        var message_hash: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.AttestationData, aggregated_attestation.data, &message_hash, allocator);

        const epoch: u64 = aggregated_attestation.data.slot;

        // Verify the aggregated signature proof
        const agg_verification_timer = zeam_metrics.lean_pq_sig_aggregated_signatures_verification_time_seconds.start();
        signature_proof.verify(public_keys.items, &message_hash, epoch) catch |err| {
            _ = agg_verification_timer.observe();
            zeam_metrics.metrics.lean_pq_sig_aggregated_signatures_invalid_total.incr();
            return err;
        };
        _ = agg_verification_timer.observe();
        zeam_metrics.metrics.lean_pq_sig_aggregated_signatures_valid_total.incr();
    }

    // Verify proposer signature (still individual)
    const proposer_attestation = signed_block.message.proposer_attestation;
    try verifySingleAttestation(
        allocator,
        state,
        @intCast(proposer_attestation.validator_id),
        &proposer_attestation.data,
        &signed_block.signature.proposer_signature,
    );
}

pub fn verifySingleAttestation(
    allocator: Allocator,
    state: *const types.BeamState,
    validator_index: usize,
    attestation_data: *const types.AttestationData,
    signatureBytes: *const types.SIGBYTES,
) !void {
    const validatorIndex = validator_index;
    const validators = state.validators.constSlice();
    if (validatorIndex >= validators.len) {
        return StateTransitionError.InvalidValidatorId;
    }

    const validator = &validators[validatorIndex];
    const pubkey = validator.getPubkey();

    const verification_timer = zeam_metrics.lean_pq_signature_attestation_verification_time_seconds.start();
    var message: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.AttestationData, attestation_data.*, &message, allocator);

    const epoch: u32 = @intCast(attestation_data.slot);

    try xmss.verifySsz(pubkey, &message, epoch, signatureBytes);
    _ = verification_timer.observe();
}

// TODO(gballet) check if beam block needs to be a pointer
pub fn apply_transition(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, opts: StateTransitionOpts) !void {
    opts.logger.debug("applying  state transition state-slot={d} block-slot={d}\n", .{ state.slot, block.slot });

    const transition_timer = zeam_metrics.lean_state_transition_time_seconds.start();
    defer _ = transition_timer.observe();

    // client is supposed to call verify_signatures outside STF to make STF prover friendly
    const validSignatures = opts.validSignatures;
    if (!validSignatures) {
        return StateTransitionError.InvalidBlockSignatures;
    }

    // prepare the pre state for this block slot
    try state.process_slots(allocator, block.slot, opts.logger);

    // process the block
    try state.process_block(allocator, block, opts.logger);

    const validateResult = opts.validateResult;
    if (validateResult) {
        // verify the post state root
        var state_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(*types.BeamState, state, &state_root, allocator);
        if (!std.mem.eql(u8, &state_root, &block.state_root)) {
            opts.logger.debug("state root={x} block root={x}\n", .{ &state_root, &block.state_root });
            return StateTransitionError.InvalidPostState;
        }
    }
}
