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

// Parallel version of verifySignatures using a work-stealing thread pool.
//
// Phase 1 (serial): validates indices, warms pubkey_cache, and computes attestation-data
// message hashes — all work that touches the non-thread-safe PublicKeyCache or may short-circuit
// on structural errors. Produces a list of prepared tasks.
//
// Phase 2 (parallel): pool.scope spawns one XMSS aggregated-signature verification per task.
// Tasks check any_err_flag before starting to mimic the serial short-circuit; the first error
// raised is the one returned. Proposer signature is verified serially at the end (single sig —
// not worth spawning).
//
// `thread_pool` is taken as anytype so state-transition itself does not have to import
// @zeam/thread-pool — that module is host-only and can't be built for zkVM targets.
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

    const VerifyTask = struct {
        signature_proof: *const types.AggregatedSignatureProof,
        public_keys: []*const xmss.HashSigPublicKey,
        message_hash: [32]u8,
        epoch: u64,
        // Per-task elapsed time (nanoseconds) measured inside the worker. We
        // record this so the post-pool emit can call `observe()` once per
        // attestation, matching the granularity of the serial path. Without
        // per-task timing the histogram would receive one batch sample per
        // block and percentiles would diverge from the serial baseline.
        elapsed_ns: u64 = 0,
        result: ?anyerror = null,
        verified: bool = false,
    };

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

    const tasks = try scratch_alloc.alloc(VerifyTask, attestations.len);

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
            .signature_proof = signature_proof,
            .public_keys = public_keys,
            .message_hash = message_hash,
            .epoch = aggregated_attestation.data.slot,
        };
    }

    // -------- Phase 2: parallel verify --------
    const Runner = struct {
        fn runScope(scope: anytype, task_slice: []VerifyTask, err_flag: *std.atomic.Value(bool)) Allocator.Error!void {
            for (task_slice) |*task| {
                try scope.spawn(runOne, .{ task, err_flag });
            }
        }

        fn runOne(task: *VerifyTask, err_flag: *std.atomic.Value(bool)) void {
            if (err_flag.load(.acquire)) return;
            task.verified = true;
            // Time the FFI verify call with a monotonic Timer so the per-task
            // sample matches what the serial path observes. `Timer.start()`
            // only fails on platforms without a monotonic clock (none of the
            // supported zeam targets) — fall through with elapsed_ns=0 if it
            // ever does, rather than poisoning the result with garbage.
            var timer = std.time.Timer.start() catch null;
            task.signature_proof.verify(task.public_keys, &task.message_hash, task.epoch) catch |err| {
                if (timer) |*t| task.elapsed_ns = t.read();
                task.result = err;
                err_flag.store(true, .release);
                return;
            };
            if (timer) |*t| task.elapsed_ns = t.read();
        }
    };

    var any_err = std.atomic.Value(bool).init(false);
    try thread_pool.scope(Runner.runScope, .{ tasks, &any_err });

    // Emit one histogram sample per verified task so the parallel path's
    // percentiles match the serial path (which observes once per
    // attestation). Mixing the two granularities into the same histogram
    // would silently distort P50/P99 across deployments.
    for (tasks) |*task| {
        if (!task.verified) continue;
        const elapsed_s: f32 = @as(f32, @floatFromInt(task.elapsed_ns)) / std.time.ns_per_s;
        zeam_metrics.lean_pq_sig_aggregated_signatures_verification_time_seconds.record(elapsed_s);
        if (task.result) |_| {
            zeam_metrics.metrics.lean_pq_sig_aggregated_signatures_invalid_total.incr();
        } else {
            zeam_metrics.metrics.lean_pq_sig_aggregated_signatures_valid_total.incr();
        }
    }
    for (tasks) |*task| {
        if (task.result) |err| return err;
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
    /// Optional precomputed `hashTreeRoot(AttestationData)` digest. When
    /// supplied, the function skips re-hashing the attestation data.
    /// Producers (e.g. `BeamNode.onGossip`) compute the hash before any
    /// lock to keep the hot path lock-free (issue #786 req. 5).
    precomputed_message_hash: ?*const [32]u8,
) !void {
    const validatorIndex = validator_index;
    const validators = state.validators.constSlice();
    if (validatorIndex >= validators.len) {
        return StateTransitionError.InvalidValidatorId;
    }

    const validator = &validators[validatorIndex];
    const pubkey = validator.getAttestationPubkey();

    const verification_timer = zeam_metrics.lean_pq_sig_attestation_verification_time_seconds.start();
    var message_buf: [32]u8 = undefined;
    const message_ptr: *const [32]u8 = if (precomputed_message_hash) |h| h else blk: {
        try zeam_utils.hashTreeRoot(types.AttestationData, attestation_data.*, &message_buf, allocator);
        break :blk &message_buf;
    };

    const epoch: u32 = @intCast(attestation_data.slot);

    // Increment total signatures counter for verification path (signatures received from wire)
    zeam_metrics.metrics.lean_pq_sig_attestation_signatures_total.incr();

    xmss.verifySsz(pubkey, message_ptr, epoch, signatureBytes) catch |err| {
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
