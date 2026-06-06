const std = @import("std");
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

// not active in PQ - zig will automatically prune this from code
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

// Verify the single merged Type-2 proof on SignedBlock.proof: split by per-component
// message binding (attestations then proposer) and run one container.verify.
pub fn verifySignatures(
    allocator: Allocator,
    state: *const types.BeamState,
    signed_block: *const types.SignedBlock,
    pubkey_cache: ?*xmss.PublicKeyCache,
    // When the caller already holds the block's hashTreeRoot (the batched
    // catch-up path precomputes it), pass it to skip a redundant re-hash;
    // pass null to compute it here. It MUST equal
    // hashTreeRoot(BeamBlock, signed_block.block) — it binds the proposer
    // component and feeds the duplicate-root collision check.
    precomputed_block_root: ?*const [32]u8,
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
    if (precomputed_block_root) |root| {
        block_root = root.*;
    } else {
        try zeam_utils.hashTreeRoot(types.BeamBlock, block.*, &block_root, ar);
    }
    // Reject a block_root that collides with any attestation data root, so the per-message
    // split/verify stays unambiguous (cryptographically negligible).
    const proposer_gop = try seen_roots.getOrPut(block_root);
    if (proposer_gop.found_existing) {
        return StateTransitionError.InvalidBlockSignatures;
    }
    messages[attestations.len] = .{ .hash = block_root, .slot = @intCast(block.slot) };

    // SignedBlock.proof IS the Type-2 container now (SSZ decoded it once at the SignedBlock
    // boundary); verify directly against it. The FFI consumes the inner raw wire.
    const verify_timer = zeam_metrics.lean_pq_sig_aggregated_signatures_verification_time_seconds.start();
    signed_block.proof.verify(pks_per_message, messages) catch {
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
            // When the post-state root doesn't match the
            // proposer's claim, log per-field hashTreeRoots of our computed
            // post-state. Comparing these across nodes (or against a known
            // healthy node's post-state at the same slot) pins down exactly
            // which `BeamState` field is the divergent one. Without this,
            // operators can only see "state_root mismatch" — they can't tell
            // whether it's `historical_block_hashes`, `latest_justified`,
            // `justifications_*`, etc. that drifted, so root-cause analysis
            // stalls. Fail-soft on per-field hash failures — still return the
            // primary error so the chain-worker handler logic is unchanged.
            opts.logger.err(
                "InvalidPostState slot={d} computed={x} expected={x}",
                .{ block.slot, &state_root, &block.state_root },
            );
            logBeamStatePerFieldRoots(allocator, state, block.slot, opts.logger, "InvalidPostState", .err_level);
            return StateTransitionError.InvalidPostState;
        }
        // Matching baseline for the InvalidPostState
        // forensics. In one observed run every zeam node hit
        // `InvalidPostState` on slots 44, 49, 52, 57 (all ethlambda-
        // proposed blocks). The failure-side per-field log tells us what
        // each field hashes to at the point of failure, but without an
        // adjacent "what does it look like when things were still working"
        // baseline we can't see where the trajectory first diverges from
        // canonical. Logging per-field on success for the same low-slot
        // window gives us the per-slot ground truth from a peer that
        // hadn't failed yet (or, post-fix, lets us confirm zeam tracks
        // the canonical trajectory). Gated to `POSTSTATE_DIAG_SLOT_MAX`
        // (= 80 slots = first ~5 min on a 4 s slot clock) so the diagnostic
        // doesn't run for the lifetime of every long-lived node — the
        // useful comparison window is the early-chain bootstrap where
        // divergence either does or doesn't happen.
        if (block.slot <= POSTSTATE_DIAG_SLOT_MAX) {
            opts.logger.info(
                "PostStateMatch slot={d} state_root={x}",
                .{ block.slot, &state_root },
            );
            logBeamStatePerFieldRoots(allocator, state, block.slot, opts.logger, "PostStateMatch", .info_level);
        }
    }
}

/// Window inside which per-field state-root diagnostics
/// are emitted on every successful state transition (in addition to the
/// always-on failure-side log). 80 slots covers the cluster of
/// `InvalidPostState`-prone slots observed in one run
/// (44, 49, 52, 57 — all ethlambda-proposed) with margin, and is bounded
/// enough that the extra log volume on a healthy node is ~80 lines per
/// process lifetime, not per slot.
const POSTSTATE_DIAG_SLOT_MAX: u64 = 80;

/// Log level selector for `logBeamStatePerFieldRoots`.
/// Failure-side calls log at `err` to surface alongside the underlying
/// state-root mismatch; success-side calls log at `info` so they don't
/// drown out real errors but stay visible in operator logs.
const PerFieldLogLevel = enum { err_level, info_level };

/// Emit per-field hashTreeRoots of a post-state. Called
/// from two sites in `apply_transition`:
///   * Failure side — when the computed post-state root doesn't match
///     the proposer's claim. `tag = "InvalidPostState"`, `level = .err_level`.
///   * Success side — for `block.slot <= POSTSTATE_DIAG_SLOT_MAX`, as a
///     ground-truth baseline so the failure case can be compared per-field
///     against the last known good post-state. `tag = "PostStateMatch"`,
///     `level = .info_level`.
/// Errors during per-field hashing are logged-and-swallowed at err level
/// regardless of the caller's chosen level — they indicate a genuine
/// runtime fault and must not be masked by an info-tagged invocation.
fn logBeamStatePerFieldRoots(
    allocator: Allocator,
    state: *const types.BeamState,
    block_slot: u64,
    logger: zeam_utils.ModuleLogger,
    tag: []const u8,
    level: PerFieldLogLevel,
) void {
    var slot_root: [32]u8 = undefined;
    var lbh_root: [32]u8 = undefined;
    var lj_root: [32]u8 = undefined;
    var lf_root: [32]u8 = undefined;
    var hbh_root: [32]u8 = undefined;
    var js_root: [32]u8 = undefined;
    var v_root: [32]u8 = undefined;
    var jr_root: [32]u8 = undefined;
    var jv_root: [32]u8 = undefined;

    zeam_utils.hashTreeRoot(u64, state.slot, &slot_root, allocator) catch |e| {
        logger.err("{s} per-field: slot hash failed: {any}", .{ tag, e });
        return;
    };
    zeam_utils.hashTreeRoot(types.BeamBlockHeader, state.latest_block_header, &lbh_root, allocator) catch |e| {
        logger.err("{s} per-field: latest_block_header hash failed: {any}", .{ tag, e });
        return;
    };
    zeam_utils.hashTreeRoot(types.Checkpoint, state.latest_justified, &lj_root, allocator) catch |e| {
        logger.err("{s} per-field: latest_justified hash failed: {any}", .{ tag, e });
        return;
    };
    zeam_utils.hashTreeRoot(types.Checkpoint, state.latest_finalized, &lf_root, allocator) catch |e| {
        logger.err("{s} per-field: latest_finalized hash failed: {any}", .{ tag, e });
        return;
    };
    zeam_utils.hashTreeRoot(types.HistoricalBlockHashes, state.historical_block_hashes, &hbh_root, allocator) catch |e| {
        logger.err("{s} per-field: historical_block_hashes hash failed: {any}", .{ tag, e });
        return;
    };
    zeam_utils.hashTreeRoot(types.JustifiedSlots, state.justified_slots, &js_root, allocator) catch |e| {
        logger.err("{s} per-field: justified_slots hash failed: {any}", .{ tag, e });
        return;
    };
    zeam_utils.hashTreeRoot(types.Validators, state.validators, &v_root, allocator) catch |e| {
        logger.err("{s} per-field: validators hash failed: {any}", .{ tag, e });
        return;
    };
    zeam_utils.hashTreeRoot(types.JustificationRoots, state.justifications_roots, &jr_root, allocator) catch |e| {
        logger.err("{s} per-field: justifications_roots hash failed: {any}", .{ tag, e });
        return;
    };
    zeam_utils.hashTreeRoot(types.JustificationValidators, state.justifications_validators, &jv_root, allocator) catch |e| {
        logger.err("{s} per-field: justifications_validators hash failed: {any}", .{ tag, e });
        return;
    };

    const args = .{
        tag,
        block_slot,
        state.slot,
        state.historical_block_hashes.len(),
        state.justified_slots.len(),
        state.justifications_roots.len(),
        &slot_root,
        &lbh_root,
        &lj_root,
        &lf_root,
        &hbh_root,
        &js_root,
        &v_root,
        &jr_root,
        &jv_root,
    };
    const fmt = "{s} per-field block_slot={d} state_slot={d} hbh_len={d} js_len={d} jr_len={d} | slot={x} lbh={x} lj={x} lf={x} hbh={x} js={x} v={x} jr={x} jv={x}";
    switch (level) {
        .err_level => logger.err(fmt, args),
        .info_level => logger.info(fmt, args),
    }
}
