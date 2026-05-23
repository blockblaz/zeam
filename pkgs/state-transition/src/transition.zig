const std = @import("std");
const ssz = @import("ssz");
const json = std.json;
const types = @import("@zeam/types");

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
    rootToSlotCache: ?*types.RootToSlotCache = null,
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

pub fn apply_raw_block(allocator: Allocator, state: *types.BeamState, block: *types.BeamBlock, logger: zeam_utils.ModuleLogger, cache: ?*types.RootToSlotCache) !void {
    // prepare pre state to process block for that slot, may be rename prepare_pre_stateCollapse comment
    const transition_timer = zeam_metrics.lean_state_transition_time_seconds.start();
    defer _ = transition_timer.observe();

    // prepare pre state to process block for that slot, may be rename prepare_pre_state
    try state.process_slots(allocator, block.slot, logger);

    // process block and modify the pre state to post state
    try state.process_block(allocator, block.*, logger, cache);

    logger.debug("extracting state root\n", .{});
    // extract the post state root
    var state_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(*types.BeamState, state, &state_root, allocator);
    block.state_root = state_root;
}

// Verify the merged Type-2 block proof: a single verify covering every body attestation plus the
// proposer's signature over the block root. Each component's (message, slot) binding is enforced
// inside xmss.verifyType2 against the layout built here. If pubkey_cache is provided, attestation
// public keys are cached; the proposer's PROPOSAL key is resolved OUTSIDE that cache (the cache is
// keyed by validator index and holds attestation keys — a proposer who also attested would
// otherwise be verified with the wrong key).
pub fn verifySignatures(
    allocator: Allocator,
    state: *const types.BeamState,
    signed_block: *const types.SignedBlock,
    pubkey_cache: ?*xmss.PublicKeyCache,
) !void {
    const block = &signed_block.block;
    const attestations = block.body.attestations.constSlice();
    const validators = state.validators.constSlice();

    // Reject over-cap blocks before the expensive Type-2 verify (a 9-15-attestation block is still
    // a structurally valid Type-2, so verify alone would accept it).
    if (attestations.len > params.MAX_ATTESTATIONS_DATA) {
        return StateTransitionError.TooManyAttestationData;
    }

    // Per-component scratch (pubkey handle arrays, message bindings) lives in this arena.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const ar = arena.allocator();

    // Without a cache we keep the PublicKey wrappers alive until after verify so their Rust
    // handles can be freed. Storage is in the arena; handles need explicit deinit.
    var pubkey_wrappers: std.ArrayList(xmss.PublicKey) = .empty;
    defer if (pubkey_cache == null) {
        for (pubkey_wrappers.items) |*wrapper| wrapper.deinit();
    };

    // Component layout: one entry per body attestation in body order, then the proposer LAST.
    const num_messages = attestations.len + 1;
    const pks_per_message = try ar.alloc([]*const xmss.HashSigPublicKey, num_messages);
    const messages = try ar.alloc(xmss.MessageBinding, num_messages);

    // Reject duplicate AttestationData: each must appear at most once. Type-2 binds components by
    // (message, slot), so duplicates would be ambiguous.
    var seen_roots = std.AutoHashMap([32]u8, void).init(ar);

    for (attestations, 0..) |aggregated_attestation, i| {
        const validator_indices = try types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, ar);

        // aggregation_bits is the SOLE binding to pubkeys (Type-2 carries no participants), so
        // validate it explicitly: non-empty, every index in range.
        if (validator_indices.items.len == 0) {
            return StateTransitionError.InvalidBlockSignatures;
        }

        const public_keys = try ar.alloc(*const xmss.HashSigPublicKey, validator_indices.items.len);
        for (validator_indices.items, 0..) |validator_index, j| {
            if (validator_index >= validators.len) {
                return StateTransitionError.InvalidValidatorId;
            }
            const pubkey_bytes = validators[validator_index].getAttestationPubkey();
            if (pubkey_cache) |cache| {
                public_keys[j] = cache.getOrPut(validator_index, pubkey_bytes) catch {
                    return StateTransitionError.InvalidBlockSignatures;
                };
            } else {
                const pubkey = xmss.PublicKey.fromBytes(pubkey_bytes) catch {
                    return StateTransitionError.InvalidBlockSignatures;
                };
                public_keys[j] = pubkey.handle;
                try pubkey_wrappers.append(ar, pubkey);
            }
        }
        pks_per_message[i] = public_keys;

        var message_hash: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.AttestationData, aggregated_attestation.data, &message_hash, ar);
        const gop = try seen_roots.getOrPut(message_hash);
        if (gop.found_existing) {
            return StateTransitionError.InvalidBlockSignatures;
        }
        messages[i] = .{ .hash = message_hash, .slot = @intCast(aggregated_attestation.data.slot) };
    }

    // Proposer component (last): proposal key, resolved outside the attestation cache.
    const proposer_index: usize = @intCast(block.proposer_index);
    if (proposer_index >= validators.len) {
        return StateTransitionError.InvalidValidatorId;
    }
    // A malformed registered proposal key is invalid validator state, not a bad signature.
    var proposer_pk = xmss.PublicKey.fromBytes(validators[proposer_index].getProposalPubkey()) catch {
        return StateTransitionError.InvalidValidatorId;
    };
    defer proposer_pk.deinit();
    const proposer_handles = try ar.alloc(*const xmss.HashSigPublicKey, 1);
    proposer_handles[0] = proposer_pk.handle;
    pks_per_message[attestations.len] = proposer_handles;

    var block_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, block.*, &block_root, ar);
    // Reject a block_root that collides with any attestation data root, so the per-message
    // split/verify stays unambiguous (cryptographically negligible).
    const proposer_gop = try seen_roots.getOrPut(block_root);
    if (proposer_gop.found_existing) {
        return StateTransitionError.InvalidBlockSignatures;
    }
    messages[attestations.len] = .{ .hash = block_root, .slot = @intCast(block.slot) };

    // SSZ-decode the Type-2 container (the on-wire form of SignedBlock.proof); the FFI consumes
    // the inner raw wire. A malformed blob is a structural rejection.
    var container: types.TypeTwoMultiSignature = undefined;
    ssz.deserialize(types.TypeTwoMultiSignature, signed_block.proof.constSlice(), &container, allocator) catch {
        return StateTransitionError.InvalidBlockSignatures;
    };
    defer container.deinit();

    const verify_timer = zeam_metrics.lean_pq_sig_aggregated_signatures_verification_time_seconds.start();
    container.verify(pks_per_message, messages) catch {
        _ = verify_timer.observe();
        zeam_metrics.metrics.lean_pq_sig_aggregated_signatures_invalid_total.incr();
        return StateTransitionError.InvalidBlockSignatures;
    };
    _ = verify_timer.observe();
    zeam_metrics.metrics.lean_pq_sig_aggregated_signatures_valid_total.incr();
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
    const pubkey = validator.getAttestationPubkey();

    const verification_timer = zeam_metrics.lean_pq_sig_attestation_verification_time_seconds.start();
    var message: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.AttestationData, attestation_data.*, &message, allocator);

    const epoch: u32 = @intCast(attestation_data.slot);

    // Increment total signatures counter for verification path (signatures received from wire)
    zeam_metrics.metrics.lean_pq_sig_attestation_signatures_total.incr();

    xmss.verifySsz(pubkey, &message, epoch, signatureBytes) catch |err| {
        _ = verification_timer.observe();
        zeam_metrics.metrics.lean_pq_sig_attestation_signatures_invalid_total.incr();
        return err;
    };
    _ = verification_timer.observe();
    zeam_metrics.metrics.lean_pq_sig_attestation_signatures_valid_total.incr();
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
    try state.process_block(allocator, block, opts.logger, opts.rootToSlotCache);

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
