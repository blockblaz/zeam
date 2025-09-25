const ssz = @import("ssz");
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");
pub const utils = @import("./utils.zig");

const zeam_utils = @import("@zeam/utils");
const debugLog = zeam_utils.zeamLog;

const params = @import("@zeam/params");

// put the active logs at debug level for now by default
pub const StateTransitionOpts = struct {
    // signatures are validated outside for keeping life simple for the STF prover
    // we will trust client will validate them however the flag here
    // represents such dependancy and assumption for STF
    validSignatures: bool = true,
    validateResult: bool = true,
    logger: zeam_utils.ModuleLogger,
};

// pub fn process_epoch(state: types.BeamState) void {
//     // right now nothing to do
//     _ = state;
//     return;
// }

// prepare the state to be the post-state of the slot
fn process_slot(allocator: Allocator, state: *types.BeamState) !void {

    // update state root in latest block header if its zero hash
    // i.e. just after processing the latest block of latest block header
    // this completes latest block header for parentRoot checks of new block

    if (std.mem.eql(u8, &state.latest_block_header.state_root, &utils.ZERO_HASH)) {
        var prev_state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamState, state.*, &prev_state_root, allocator);
        state.latest_block_header.state_root = prev_state_root;
    }
}

// prepare the state to be pre state of the slot
fn process_slots(allocator: Allocator, state: *types.BeamState, slot: types.Slot, logger: zeam_utils.ModuleLogger) !void {
    if (slot <= state.slot) {
        logger.err("Invalid block slot={d} >= pre-state slot={d}\n", .{ slot, state.slot });
        return StateTransitionError.InvalidPreState;
    }

    while (state.slot < slot) {
        try process_slot(allocator, state);
        state.slot += 1;
    }
}

pub fn is_justifiable_slot(finalized: types.Slot, candidate: types.Slot) !bool {
    if (candidate < finalized) {
        return StateTransitionError.InvalidJustifiableSlot;
    }

    const delta: f32 = @floatFromInt(candidate - finalized);
    if (delta <= 5) {
        return true;
    }
    const delta_x2: f32 = @mod(std.math.pow(f32, delta, 0.5), 1);
    if (delta_x2 == 0) {
        return true;
    }
    const delta_x2_x: f32 = @mod(std.math.pow(f32, delta + 0.25, 0.5), 1);
    if (delta_x2_x == 0.5) {
        return true;
    }

    return false;
}

fn process_block_header(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, logger: zeam_utils.ModuleLogger) !void {
    logger.debug("process block header\n", .{});

    // 1. match state and block slot
    if (state.slot != block.slot) {
        logger.err("process-block-header: invalid mismatching state-slot={} != block-slot={}", .{ state.slot, block.slot });
        return StateTransitionError.InvalidPreState;
    }

    // 2. match state's latest block header and block slot
    if (state.latest_block_header.slot >= block.slot) {
        logger.err("process-block-header: invalid future latest_block_header-slot={} >= block-slot={}", .{ state.latest_block_header.slot, block.slot });
        return StateTransitionError.InvalidLatestBlockHeader;
    }

    // 3. check proposer is correct
    const correct_proposer_index = block.slot % state.config.num_validators;
    if (block.proposer_index != correct_proposer_index) {
        logger.err("process-block-header: invalid proposer={d} slot={d} correct-proposer={d}", .{ block.proposer_index, block.slot, correct_proposer_index });
        return StateTransitionError.InvalidProposer;
    }

    // 4. verify latest block header is the parent
    var head_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlockHeader, state.latest_block_header, &head_root, allocator);
    if (!std.mem.eql(u8, &head_root, &block.parent_root)) {
        logger.err("state root={x:02} block root={x:02}\n", .{ head_root, block.parent_root });
        return StateTransitionError.InvalidParentRoot;
    }

    // update justified and finalized with parent root in state if this is the first block post genesis
    if (state.latest_block_header.slot == 0) {
        // fixed  length array structures should just be copied over
        state.latest_justified.root = block.parent_root;
        state.latest_finalized.root = block.parent_root;
    }

    // extend historical block hashes and justified slots structures using SSZ Lists directly
    try state.historical_block_hashes.append(block.parent_root);
    // if parent is genesis it is already justified
    try state.justified_slots.append(if (state.latest_block_header.slot == 0) true else false);

    const block_slot: usize = @intCast(block.slot);
    const missed_slots: usize = @intCast(block_slot - state.latest_block_header.slot - 1);
    for (0..missed_slots) |i| {
        _ = i;
        try state.historical_block_hashes.append(utils.ZERO_HASH);
        try state.justified_slots.append(false);
    }
    logger.debug("processed missed_slots={d} justified_slots={any}, historical_block_hashes={any}", .{ missed_slots, state.justified_slots.len(), state.historical_block_hashes.len() });

    state.latest_block_header = try utils.blockToLatestBlockHeader(allocator, block);
}

// not active in PQ devnet0 - zig will automatically prune this from code
fn process_execution_payload_header(state: *types.BeamState, block: types.BeamBlock) !void {
    const expected_timestamp = state.genesis_time + block.slot * params.SECONDS_PER_SLOT;
    if (expected_timestamp != block.body.execution_payload_header.timestamp) {
        return StateTransitionError.InvalidExecutionPayloadHeaderTimestamp;
    }
}

fn process_operations(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, logger: zeam_utils.ModuleLogger) !void {
    // 1. process attestations
    try process_attestations(allocator, state, block.body.attestations, logger);
}

fn process_attestations(allocator: Allocator, state: *types.BeamState, attestations: types.SignedVotes, logger: zeam_utils.ModuleLogger) !void {
    logger.debug("process attestations slot={d} \n prestate:historical hashes={d} justified slots ={d} votes={d}, ", .{ state.slot, state.historical_block_hashes.len(), state.justified_slots.len(), attestations.constSlice().len });
    logger.debug("prestate justified={any} finalized={any}", .{ state.latest_justified, state.latest_finalized });

    // work directly with SSZ types
    // historical_block_hashes and justified_slots are already SSZ types in state

    var justifications: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer {
        var iterator = justifications.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.value_ptr.*);
        }
    }
    errdefer justifications.deinit(allocator);
    try loadJustifications(allocator, &justifications, state, logger);

    // need to cast to usize for slicing ops but does this makes the STF target arch dependent?
    const num_validators: usize = @intCast(state.config.num_validators);
    for (attestations.constSlice()) |signed_vote| {
        const validator_id: usize = @intCast(signed_vote.validator_id);
        const vote = signed_vote.message;
        // check if vote is sane
        const source_slot: usize = @intCast(vote.source.slot);
        const target_slot: usize = @intCast(vote.target.slot);
        logger.debug("processing vote={any} validator_id={d}\n....\n", .{ vote, validator_id });

        if (source_slot >= state.justified_slots.len()) {
            return StateTransitionError.InvalidSlotIndex;
        }
        if (target_slot >= state.justified_slots.len()) {
            return StateTransitionError.InvalidSlotIndex;
        }
        if (source_slot >= state.historical_block_hashes.len()) {
            return StateTransitionError.InvalidSlotIndex;
        }
        if (target_slot >= state.historical_block_hashes.len()) {
            return StateTransitionError.InvalidSlotIndex;
        }

        const is_source_justified = state.justified_slots.get(source_slot);
        const is_target_already_justified = state.justified_slots.get(target_slot);
        const has_correct_source_root = std.mem.eql(u8, &vote.source.root, &state.historical_block_hashes.get(source_slot));
        const has_correct_target_root = std.mem.eql(u8, &vote.target.root, &state.historical_block_hashes.get(target_slot));
        const target_not_ahead = target_slot <= source_slot;
        const is_target_justifiable = try is_justifiable_slot(state.latest_finalized.slot, target_slot);

        if (!is_source_justified or
            // not present in 3sf mini but once a target is justified no need to run loop
            // as we remove the target from justifications map as soon as its justified
            is_target_already_justified or
            !has_correct_source_root or
            !has_correct_target_root or
            target_not_ahead or
            !is_target_justifiable)
        {
            logger.debug("skipping the vote as not viable: !(source_justified={}) or target_already_justified={} !(correct_source_root={}) or !(correct_target_root={}) or target_not_ahead={} or !(target_justifiable={})", .{
                is_source_justified,
                is_target_already_justified,
                has_correct_source_root,
                has_correct_target_root,
                target_not_ahead,
                is_target_justifiable,
            });
            continue;
        }

        if (validator_id >= num_validators) {
            return StateTransitionError.InvalidValidatorId;
        }

        var target_justifications = justifications.get(vote.target.root) orelse targetjustifications: {
            var targetjustifications = try allocator.alloc(u8, num_validators);
            for (0..targetjustifications.len) |i| {
                targetjustifications[i] = 0;
            }
            try justifications.put(allocator, vote.target.root, targetjustifications);
            break :targetjustifications targetjustifications;
        };

        target_justifications[validator_id] = 1;
        try justifications.put(allocator, vote.target.root, target_justifications);
        var target_justifications_count: usize = 0;
        for (target_justifications) |justified| {
            if (justified == 1) {
                target_justifications_count += 1;
            }
        }
        logger.debug("target jcount={d}: {any} justifications={any}\n", .{ target_justifications_count, vote.target.root, target_justifications });

        // as soon as we hit the threshold do justifications
        // note that this simplification works if weight of each validator is 1
        //
        // ceilDiv is not available so this seems like a less compute intesive way without
        // requring floar division, can be further optimized
        if (3 * target_justifications_count >= 2 * num_validators) {
            state.latest_justified = vote.target;
            state.justified_slots.set(target_slot, true);
            _ = justifications.remove(vote.target.root);
            logger.debug("\n\n\n-----------------HURRAY JUSTIFICATION ------------\n{any}\n--------------\n---------------\n-------------------------\n\n\n", .{state.latest_justified});

            // source is finalized if target is the next valid justifiable hash
            var can_target_finalize = true;
            for (source_slot + 1..target_slot) |check_slot| {
                if (try is_justifiable_slot(state.latest_finalized.slot, check_slot)) {
                    can_target_finalize = false;
                    break;
                }
            }
            logger.debug("----------------can_target_finalize ({d})={any}----------\n\n", .{ source_slot, can_target_finalize });
            if (can_target_finalize == true) {
                state.latest_finalized = vote.source;
                logger.debug("\n\n\n-----------------DOUBLE HURRAY FINALIZATION ------------\n{any}\n--------------\n---------------\n-------------------------\n\n\n", .{state.latest_finalized});
            }
        }
    }

    try flattenJustifications(allocator, &justifications, state);

    logger.debug("poststate:historical hashes={d} justified slots ={d}\n justifications_roots:{d}\n justifications_validators={d}\n", .{ state.historical_block_hashes.len(), state.justified_slots.len(), state.justifications_roots.len(), state.justifications_validators.len() });
    logger.debug("poststate: justified={any} finalized={any}", .{ state.latest_justified, state.latest_finalized });
}

/// Helper function to load justifications from state into a map
fn loadJustifications(allocator: Allocator, justifications: *std.AutoHashMapUnmanaged(types.Root, []u8), state: *types.BeamState, logger: zeam_utils.ModuleLogger) !void {
    // need to cast to usize for slicing ops but does this makes the STF target arch dependent?
    const num_validators: usize = @intCast(state.config.num_validators);
    // Initialize justifications from state
    for (state.justifications_roots.constSlice(), 0..) |blockRoot, i| {
        const validator_data = try allocator.alloc(u8, num_validators);
        // Copy existing justification data if available, otherwise return error
        for (validator_data, 0..) |*byte, j| {
            const bit_index = i * num_validators + j;
            if (bit_index >= state.justifications_validators.len()) {
                logger.err("Invalid bit_index={d} parsing justification roots={d} justification entries={d} num_validators={d} access  range (i={d}): {d}..{d} err={any}", .{
                    bit_index,
                    state.justifications_roots.len(),
                    state.justifications_validators.len(),
                    num_validators,
                    bit_index,
                    i,
                    i * num_validators,
                    (i + 1) * num_validators,
                });
                return StateTransitionError.InvalidJustificationIndex;
            }
            byte.* = if (state.justifications_validators.get(bit_index)) 1 else 0;
        }
        try justifications.put(allocator, blockRoot, validator_data);
    }
}

/// Helper function to flatten justifications map back to state arrays
fn flattenJustifications(allocator: Allocator, justifications: *std.AutoHashMapUnmanaged(types.Root, []u8), state: *types.BeamState) !void {
    // Lists are now heap allocated ArrayLists using the allocator
    // Deinit existing lists and reinitialize
    state.justifications_roots.deinit();
    state.justifications_validators.deinit();
    state.justifications_roots = try types.JustificationsRoots.init(allocator);
    state.justifications_validators = try types.JustificationsValidators.init(allocator);

    // First, collect all keys
    var iterator = justifications.iterator();
    while (iterator.next()) |kv| {
        try state.justifications_roots.append(kv.key_ptr.*);
    }

    // Sort the roots, confirm this sorting via a test
    std.mem.sortUnstable(types.Root, state.justifications_roots.slice(), {}, struct {
        fn lessThanFn(_: void, a: types.Root, b: types.Root) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.lessThanFn);

    // Now iterate over sorted roots and flatten validators in order
    for (state.justifications_roots.constSlice()) |root| {
        const rootSlice = justifications.get(root) orelse unreachable;
        // append individual bits for validator justifications
        // have a batch set method to set it since eventual num vals are div by 8
        // and hence the vector can be fully appeneded as bytes
        for (rootSlice) |validator_bit| {
            try state.justifications_validators.append(validator_bit == 1);
        }
    }
}

fn process_block(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, logger: zeam_utils.ModuleLogger) !void {
    // start block processing
    try process_block_header(allocator, state, block, logger);
    // PQ devner-0 has no execution
    // try process_execution_payload_header(state, block);
    try process_operations(allocator, state, block, logger);
}

pub fn apply_raw_block(allocator: Allocator, state: *types.BeamState, block: *types.BeamBlock, logger: zeam_utils.ModuleLogger) !void {
    // prepare pre state to process block for that slot, may be rename prepare_pre_state
    try process_slots(allocator, state, block.slot, logger);

    // process block and modify the pre state to post state
    try process_block(allocator, state, block.*, logger);

    logger.debug("extracting state root\n", .{});
    // extract the post state root
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, state.*, &state_root, allocator);
    block.state_root = state_root;
}

// fill this up when we have signature scheme
pub fn verify_signatures(signedBlock: types.SignedBeamBlock) !void {
    _ = signedBlock;
}

// TODO(gballet) check if beam block needs to be a pointer
pub fn apply_transition(allocator: Allocator, state: *types.BeamState, signedBlock: types.SignedBeamBlock, opts: StateTransitionOpts) !void {
    const block = signedBlock.message;
    opts.logger.debug("applying  state transition state-slot={d} block-slot={d}\n", .{ state.slot, block.slot });

    // client is supposed to call verify_signatures outside STF to make STF prover friendly
    const validSignatures = opts.validSignatures;
    if (!validSignatures) {
        return StateTransitionError.InvalidBlockSignatures;
    }

    // prepare the pre state for this block slot
    try process_slots(allocator, state, block.slot, opts.logger);
    // process the block
    try process_block(allocator, state, block, opts.logger);

    const validateResult = opts.validateResult;
    if (validateResult) {
        // verify the post state root
        var state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamState, state.*, &state_root, allocator);
        if (!std.mem.eql(u8, &state_root, &block.state_root)) {
            opts.logger.debug("state root={x:02} block root={x:02}\n", .{ state_root, block.state_root });
            return StateTransitionError.InvalidPostState;
        }
    }
}

pub const StateTransitionError = error{ InvalidParentRoot, InvalidPreState, InvalidPostState, InvalidExecutionPayloadHeaderTimestamp, InvalidJustifiableSlot, InvalidValidatorId, InvalidBlockSignatures, InvalidLatestBlockHeader, InvalidProposer, InvalidJustificationIndex, InvalidSlotIndex };
