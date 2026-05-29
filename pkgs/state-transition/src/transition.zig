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

// Verify aggregated signatures using AggregatedSignatureProof
// If pubkey_cache is provided, public keys are cached to avoid repeated SSZ deserialization.
// This can significantly reduce CPU overhead when processing many blocks.
// TODO: benchmark and compare with verifySignaturesParallel, see if the scheduling overhead
// on thread pool overcomes the benefit of parallelizing the verification.
pub fn verifySignatures(
    allocator: Allocator,
    state: *const types.BeamState,
    signed_block: *const types.SignedBlock,
    pubkey_cache: ?*xmss.PublicKeyCache,
) !void {
    const attestations = signed_block.block.body.attestations.constSlice();
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
            const pubkey_bytes = validator.getAttestationPubkey();

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

    // Verify proposer signature over hash_tree_root(block) using proposal key
    const proposer_index: usize = @intCast(signed_block.block.proposer_index);
    if (proposer_index >= validators.len) {
        return StateTransitionError.InvalidValidatorId;
    }
    const proposer = &validators[proposer_index];
    const proposal_pubkey = proposer.getProposalPubkey();

    var block_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.block, &block_root, allocator);

    const block_epoch: u32 = @intCast(signed_block.block.slot);
    try xmss.verifySsz(proposal_pubkey, &block_root, block_epoch, &signed_block.signature.proposer_signature);
}

// Parallel version of verifySignatures.
//
// Phase 1 (serial): validates indices, warms pubkey_cache, and computes attestation-data
// message hashes — all work that touches the non-thread-safe PublicKeyCache or may short-circuit
// on structural errors. Produces a list of prepared tasks.
//
// Phase 2 (parallel): hands the prepared batch to Rust so XMSS verification runs on the same
// capped rayon pool as recursive aggregation. `thread_pool` is intentionally unused here; it is
// kept in the signature so call sites do not need a separate serial/parallel dispatch surface.
// Proposer signature is verified serially at the end (single sig — not worth batching).
pub fn verifySignaturesParallel(
    allocator: Allocator,
    state: *const types.BeamState,
    signed_block: *const types.SignedBlock,
    pubkey_cache: ?*xmss.PublicKeyCache,
    thread_pool: anytype,
) !void {
    const attestations = signed_block.block.body.attestations.constSlice();
    const signature_proofs = signed_block.signature.attestation_signatures.constSlice();

    if (attestations.len != signature_proofs.len) {
        return StateTransitionError.InvalidBlockSignatures;
    }

    const validators = state.validators.constSlice();
    _ = thread_pool;

    // All per-task scratch (pubkey handle arrays, pubkey_wrappers when cache is absent)
    // lives in this arena and is freed with one call after the parallel phase returns.
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const scratch_alloc = scratch.allocator();

    // If no cache is provided we must keep the PublicKey wrappers alive until after verify;
    // collect them here so their Rust handles are freed when we unwind.
    var pubkey_wrappers: std.ArrayList(xmss.PublicKey) = .empty;
    // The ArrayList storage itself lives in scratch and is freed with scratch.deinit(), but
    // the Rust handles wrapped by each PublicKey require explicit deinit on every path out.
    defer if (pubkey_cache == null) {
        for (pubkey_wrappers.items) |*wrapper| wrapper.deinit();
    };

    const tasks = try scratch_alloc.alloc(xmss.AggregatedPayloadVerifyBatch, attestations.len);

    // -------- Phase 1: serial pre-warm --------
    for (attestations, signature_proofs, 0..) |aggregated_attestation, *signature_proof, i| {
        var validator_indices = try types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, allocator);
        defer validator_indices.deinit(allocator);

        var participant_indices = try types.aggregationBitsToValidatorIndices(&signature_proof.participants, allocator);
        defer participant_indices.deinit(allocator);

        if (validator_indices.items.len != participant_indices.items.len) {
            return StateTransitionError.InvalidBlockSignatures;
        }
        for (validator_indices.items, participant_indices.items) |att_idx, proof_idx| {
            if (att_idx != proof_idx) {
                return StateTransitionError.InvalidBlockSignatures;
            }
        }

        const public_keys = try scratch_alloc.alloc(*const xmss.HashSigPublicKey, validator_indices.items.len);

        for (validator_indices.items, 0..) |validator_index, j| {
            if (validator_index >= validators.len) {
                return StateTransitionError.InvalidValidatorId;
            }
            const validator = &validators[validator_index];
            const pubkey_bytes = validator.getAttestationPubkey();

            if (pubkey_cache) |cache| {
                const pk_handle = cache.getOrPut(validator_index, pubkey_bytes) catch {
                    return StateTransitionError.InvalidBlockSignatures;
                };
                public_keys[j] = pk_handle;
            } else {
                const pubkey = xmss.PublicKey.fromBytes(pubkey_bytes) catch {
                    return StateTransitionError.InvalidBlockSignatures;
                };
                public_keys[j] = pubkey.handle;
                try pubkey_wrappers.append(scratch_alloc, pubkey);
            }
        }

        var message_hash: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.AttestationData, aggregated_attestation.data, &message_hash, allocator);

        tasks[i] = .{
            .public_keys = public_keys,
            .message_hash = message_hash,
            .epoch = @intCast(aggregated_attestation.data.slot),
            .agg_sig = &signature_proof.proof_data,
        };
    }

    // -------- Phase 2: rayon batch verify --------
    const start_ns = zeam_utils.monotonicTimestampNs();
    xmss.verifyAggregatedPayloadBatch(scratch_alloc, tasks) catch |err| {
        const end_ns = zeam_utils.monotonicTimestampNs();
        const elapsed_s: f32 = @as(f32, @floatFromInt(if (end_ns >= start_ns) end_ns - start_ns else 0)) / std.time.ns_per_s;
        zeam_metrics.lean_pq_sig_aggregated_signatures_verification_time_seconds.record(elapsed_s);
        zeam_metrics.metrics.lean_pq_sig_aggregated_signatures_invalid_total.incr();
        return err;
    };
    const end_ns = zeam_utils.monotonicTimestampNs();
    const elapsed_s: f32 = @as(f32, @floatFromInt(if (end_ns >= start_ns) end_ns - start_ns else 0)) / std.time.ns_per_s;
    const per_task_elapsed_s = if (tasks.len > 0) elapsed_s / @as(f32, @floatFromInt(tasks.len)) else 0;
    for (tasks) |_| {
        zeam_metrics.lean_pq_sig_aggregated_signatures_verification_time_seconds.record(per_task_elapsed_s);
        zeam_metrics.metrics.lean_pq_sig_aggregated_signatures_valid_total.incr();
    }

    // Proposer signature — single verify, do it serially.
    const proposer_index: usize = @intCast(signed_block.block.proposer_index);
    if (proposer_index >= validators.len) {
        return StateTransitionError.InvalidValidatorId;
    }
    const proposer = &validators[proposer_index];
    const proposal_pubkey = proposer.getProposalPubkey();

    var block_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.block, &block_root, allocator);

    const block_epoch: u32 = @intCast(signed_block.block.slot);
    try xmss.verifySsz(proposal_pubkey, &block_root, block_epoch, &signed_block.signature.proposer_signature);
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
            // #942 follow-up: when the post-state root doesn't match the
            // proposer's claim, log per-field hashTreeRoots of OUR computed
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
        // #942 follow-up: matching baseline for the InvalidPostState
        // forensics. On the 2026-05-29 devnet every zeam node hit
        // `InvalidPostState` on slots 44, 49, 52, 57 (all ethlambda-
        // proposed blocks). The failure-side per-field log tells us what
        // each field hashes to AT THE POINT OF FAILURE, but without an
        // adjacent "what does it look like when things were still working"
        // baseline we can't see WHERE the trajectory first diverges from
        // canonical. Logging per-field on SUCCESS for the same low-slot
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

/// #942 follow-up: window inside which per-field state-root diagnostics
/// are emitted on every successful state transition (in addition to the
/// always-on failure-side log). 80 slots covers the cluster of
/// `InvalidPostState`-prone slots observed on the 2026-05-29 devnet
/// (44, 49, 52, 57 — all ethlambda-proposed) with margin, and is bounded
/// enough that the extra log volume on a healthy node is ~80 lines per
/// process lifetime, not per slot.
const POSTSTATE_DIAG_SLOT_MAX: u64 = 80;

/// #942 follow-up: log level selector for `logBeamStatePerFieldRoots`.
/// Failure-side calls log at `err` to surface alongside the underlying
/// state-root mismatch; success-side calls log at `info` so they don't
/// drown out real errors but stay visible in operator logs.
const PerFieldLogLevel = enum { err_level, info_level };

/// #942 follow-up: emit per-field hashTreeRoots of a post-state. Called
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
