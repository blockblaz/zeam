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
    logger: *zeam_utils.ZeamLogger,
};

// pub fn process_epoch(state: types.BeamState) void {
//     // right now nothing to do
//     _ = state;
//     return;
// }

// prepare the state to be the post-state of the slot
pub fn process_slot(allocator: Allocator, state: *types.BeamState) !void {

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
pub fn process_slots(allocator: Allocator, state: *types.BeamState, slot: types.Slot, logger: *zeam_utils.ZeamLogger) !void {
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

fn process_block_header(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, logger: *zeam_utils.ZeamLogger) !void {
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

    // extend historical block hashes and justified slots structures
    // can optimize to have a "cached" state where these sttructures are already in consimable format
    var historical_block_hashes = std.ArrayList(types.Root).fromOwnedSlice(allocator, state.historical_block_hashes);
    var justified_slots = std.ArrayList(u8).fromOwnedSlice(allocator, state.justified_slots);

    try historical_block_hashes.append(block.parent_root);
    // if parent is genesis it is already justified
    try justified_slots.append(if (state.latest_block_header.slot == 0) 1 else 0);

    const block_slot: usize = @intCast(block.slot);
    const missed_slots: usize = @intCast(block_slot - state.latest_block_header.slot - 1);
    for (0..missed_slots) |i| {
        _ = i;
        try historical_block_hashes.append(utils.ZERO_HASH);
        try justified_slots.append(0);
    }
    logger.debug("processed missed_slots={d} justified_slots={any}, historical_block_hashes={any}", .{ missed_slots, justified_slots.items, historical_block_hashes.items });

    // again "cached" state would optimize make this avoidable till the very end of state root calc
    state.historical_block_hashes = try historical_block_hashes.toOwnedSlice();
    state.justified_slots = try justified_slots.toOwnedSlice();

    state.latest_block_header = try utils.blockToLatestBlockHeader(allocator, block);
}

// not active in PQ devnet0 - zig will automatically prune this from code
fn process_execution_payload_header(state: *types.BeamState, block: types.BeamBlock) !void {
    const expected_timestamp = state.genesis_time + block.slot * params.SECONDS_PER_SLOT;
    if (expected_timestamp != block.body.execution_payload_header.timestamp) {
        return StateTransitionError.InvalidExecutionPayloadHeaderTimestamp;
    }
}

fn process_operations(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, logger: *zeam_utils.ZeamLogger) !void {
    // 1. process attestations
    try process_attestations(allocator, state, block.body.attestations, logger);
}

fn process_attestations(allocator: Allocator, state: *types.BeamState, attestations: []types.SignedVote, logger: *zeam_utils.ZeamLogger) !void {
    logger.debug("\n\n===================\nprocess opetationg slot={d} \n prestate:historical hashes={d} justified slots ={any}, ", .{ state.slot, state.historical_block_hashes.len, state.justified_slots });
    logger.debug("prestate justified={any} finalized={any}\n.........\n\n", .{ state.latest_justified, state.latest_finalized });

    // transform state data into consumable format, generally one would keep a `cached`/consumable
    // copy of state but we will get to that later especially w.r.t. proving
    // prep data
    var historical_block_hashes = std.ArrayList(types.Root).fromOwnedSlice(allocator, state.historical_block_hashes);
    var justified_slots = std.ArrayList(u8).fromOwnedSlice(allocator, state.justified_slots);

    // prep the justifications map
    var justifications = std.AutoHashMap(types.Root, []u8).init(allocator);
    // need to cast to usize for slicing ops but does this makes the STF target arch dependent?
    const num_validators: usize = @intCast(state.config.num_validators);
    for (state.justifications_roots) |blockRoot| {
        for (0..num_validators) |i| {
            justifications.put(blockRoot, state.justifications_validators[i * num_validators .. (i + 1) * num_validators]) catch |e| {
                logger.err("Invalid justifications parsing justification entries={d} num_validators={d} access range (i={d}): {d}..{d} err={any}", .{
                    //
                    state.justifications_validators.len,
                    num_validators,
                    i,
                    i * num_validators,
                    (i + 1) * num_validators,
                    e,
                });
                return e;
            };
        }
    }

    for (attestations) |signed_vote| {
        const validator_id: usize = @intCast(signed_vote.validator_id);
        const vote = signed_vote.message;
        // check if vote is sane
        const source_slot: usize = @intCast(vote.source.slot);
        const target_slot: usize = @intCast(vote.target.slot);
        logger.debug("processing vote={any} validator_id={d}\n....\n", .{ vote, validator_id });

        const is_source_justified = justified_slots.items[source_slot] == 1;
        const is_target_already_justified = justified_slots.items[target_slot] == 1;
        const has_correct_source_root = std.mem.eql(u8, &vote.source.root, &historical_block_hashes.items[source_slot]);
        const has_correct_target_root = std.mem.eql(u8, &vote.target.root, &historical_block_hashes.items[target_slot]);
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
            try justifications.put(vote.target.root, targetjustifications);
            break :targetjustifications targetjustifications;
        };

        target_justifications[validator_id] = 1;
        try justifications.put(vote.target.root, target_justifications);
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
            justified_slots.items[target_slot] = 1;
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

    // reconstiture back the state vectors
    state.historical_block_hashes = try historical_block_hashes.toOwnedSlice();
    state.justified_slots = try justified_slots.toOwnedSlice();

    var justifications_roots = std.ArrayList(types.Root).init(allocator);
    var justifications_validators = std.ArrayList(u8).init(allocator);
    var iterator = justifications.iterator();
    while (iterator.next()) |kv| {
        try justifications_roots.append(kv.key_ptr.*);
        try justifications_validators.appendSlice(kv.value_ptr.*);
    }

    allocator.free(state.justifications_roots);
    allocator.free(state.justifications_validators);
    state.justifications_roots = try justifications_roots.toOwnedSlice();
    state.justifications_validators = try justifications_validators.toOwnedSlice();

    for (state.justifications_roots) |root| {
        _ = justifications.remove(root);
    }

    logger.debug("\n---------------\npoststate:historical hashes={d} justified slots ={any}\n justifications_roots:{any}\n justifications_validators= {any}\n", .{ state.historical_block_hashes.len, state.justified_slots, state.justifications_roots, state.justifications_validators });
    logger.debug("poststate: justified={any} finalized={any}\n---------------\n------------\n\n\n", .{ state.latest_justified, state.latest_finalized });
}

pub fn process_block(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, logger: *zeam_utils.ZeamLogger) !void {
    // start block processing
    try process_block_header(allocator, state, block, logger);
    // PQ devner-0 has no execution
    // try process_execution_payload_header(state, block);
    try process_operations(allocator, state, block, logger);
}

pub fn apply_raw_block(allocator: Allocator, state: *types.BeamState, block: *types.BeamBlock, logger: *zeam_utils.ZeamLogger) !void {
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
    const logger = opts.logger;
    const block = signedBlock.message;
    logger.debug("applying  state transition state-slot={d} block-slot={d}\n", .{ state.slot, block.slot });

    // client is supposed to call verify_signatures outside STF to make STF prover friendly
    const validSignatures = opts.validSignatures;
    if (!validSignatures) {
        return StateTransitionError.InvalidBlockSignatures;
    }

    // prepare the pre state for this block slot
    try process_slots(allocator, state, block.slot, logger);
    // process the block
    try process_block(allocator, state, block, logger);

    const validateResult = opts.validateResult;
    if (validateResult) {
        // verify the post state root
        var state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamState, state.*, &state_root, allocator);
        if (!std.mem.eql(u8, &state_root, &block.state_root)) {
            logger.debug("state root={x:02} block root={x:02}\n", .{ state_root, block.state_root });
            return StateTransitionError.InvalidPostState;
        }
    }
}

pub const StateTransitionError = error{ InvalidParentRoot, InvalidPreState, InvalidPostState, InvalidExecutionPayloadHeaderTimestamp, InvalidJustifiableSlot, InvalidValidatorId, InvalidBlockSignatures, InvalidLatestBlockHeader, InvalidProposer };
