const ssz = @import("ssz");
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");
pub const utils = @import("./utils.zig");

const zeam_utils = @import("@zeam/utils");
const log = zeam_utils.zeamLog;
const getLogger = zeam_utils.getLogger;

const params = @import("@zeam/params");

// put the active logs at debug level for now by default
pub const StateTransitionOpts = struct { activeLogLevel: std.log.Level = std.log.Level.debug };

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
pub fn process_slots(allocator: Allocator, state: *types.BeamState, slot: types.Slot) !void {
    while (state.slot < slot) {
        try process_slot(allocator, state);
        // There might not be epoch processing in beam
        // if ((state.slot + 1) % SLOTS_PER_EPOCH == 0) {
        //     process_epoch(state);
        // }

        state.slot += 1;
    }
}

fn is_justifiable_slot(finalized: types.Slot, candidate: types.Slot) !bool {
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

fn process_block_header(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock) !void {
    // very basic process block header
    if (state.slot != block.slot) {
        log("state slot={} block slot={}", .{ state.slot, block.slot }) catch @panic("error printing invalid block slot");
        return StateTransitionError.InvalidPreState;
    }

    var head_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlockHeader, state.latest_block_header, &head_root, allocator);
    if (!std.mem.eql(u8, &head_root, &block.parent_root)) {
        log("state root={x:02} block root={x:02}\n", .{ head_root, block.parent_root }) catch @panic("error printing invalid parent root");
        return StateTransitionError.InvalidParentRoot;
    }

    state.latest_block_header = try utils.blockToLatestBlockHeader(allocator, block);
}

fn process_execution_payload_header(state: *types.BeamState, block: types.BeamBlock) !void {
    const expected_timestamp = state.genesis_time + block.slot * params.SECONDS_PER_SLOT;
    if (expected_timestamp != block.body.execution_payload_header.timestamp) {
        return StateTransitionError.InvalidExecutionPayloadHeaderTimestamp;
    }
}

fn process_operations(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock) !void {
    // transform state data into consumable format, generally one would keep a `cached`/consumable
    // copy of state but we will get to that later especially w.r.t. proving
    // prep data
    var historical_block_hashes = std.ArrayList(types.Root).fromOwnedSlice(allocator, state.historical_block_hashes);
    std.debug.print("process opetationg blockslot={d} historical hashes={d} pre state = \n{any}\n", .{ block.slot, historical_block_hashes.items.len, state });

    var justified_slots = std.ArrayList(u8).fromOwnedSlice(allocator, state.justified_slots);
    // prep the justifications map
    var justifications = std.AutoHashMap(types.Root, []u8).init(allocator);

    const num_validators = state.config.num_validators;
    for (state.justifications_roots) |blockRoot| {
        for (0..state.config.num_validators) |i| {
            try justifications.put(blockRoot, state.justifications_validators[i * num_validators .. (i + 1) * num_validators]);
        }
    }

    // self injected handling to make sure we can still have genesis block at 0
    // otherwise we need genesis block at 1 because genesis state need to have justified slots
    // historical hashes set which we can't do with genesis block since it becomes cyclic
    // dependancy because of block stateroot requirement
    if (state.slot == 1) {
        // parent is genesis
        justified_slots.items[0] = 1;
        historical_block_hashes.items[0] = block.parent_root;
        state.latest_justified.root = block.parent_root;
        state.lastest_finalized.root = block.parent_root;
    } else {
        try historical_block_hashes.append(block.parent_root);
        try justified_slots.append(0);
    }

    const missed_slots = block.slot - historical_block_hashes.items.len;
    for (0..missed_slots) |i| {
        _ = i;
        try justified_slots.append(0);
        // we push zero hash instead of none to keep our SSZ structure simple
        // in applying votes we can eliminate this issue by having source/target to be non zerohash
        // because genesis is always justified and finalized
        try historical_block_hashes.append(utils.ZERO_HASH);
    }

    for (block.body.votes) |vote| {
        // check if vote is sane
        if (justified_slots.items[vote.source.slot] != 1 or
            !std.mem.eql(u8, &vote.source.root, &historical_block_hashes.items[vote.source.slot]) or
            !std.mem.eql(u8, &vote.target.root, &historical_block_hashes.items[vote.target.slot]) or
            vote.target.slot <= vote.source.slot or
            try is_justifiable_slot(state.lastest_finalized.slot, vote.target.slot) == false)
        {
            continue;
        }
        if (vote.validator_id >= num_validators) {
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

        target_justifications[vote.validator_id] = 1;
        var target_justifications_count: usize = 0;
        for (target_justifications) |justified| {
            if (justified == 1) {
                target_justifications_count += 1;
            }
        }

        // as soon as we hit the threshold do justifications
        // note that this simplification works if weight of each validator is 1
        if (target_justifications_count == @divFloor(num_validators * 2, 3)) {
            state.latest_justified = vote.target;
            justified_slots.items[vote.target.slot] = 1;
            _ = justifications.remove(vote.target.root);
        }

        // source is finalized if target is the next valid justifiable hash
        var can_target_finalize = true;
        for (vote.source.slot + 1..vote.target.slot) |check_slot| {
            if (try is_justifiable_slot(state.lastest_finalized.slot, check_slot)) {
                can_target_finalize = false;
                break;
            }
        }
        if (can_target_finalize == true) {
            state.lastest_finalized = vote.source;
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
    std.debug.print("post opetationg blockslot={d} historical hashes={d} post state = \n{any}\n", .{ block.slot, state.historical_block_hashes.len, state });
}

pub fn process_block(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock) !void {
    // start block processing
    try process_block_header(allocator, state, block);
    try process_execution_payload_header(state, block);
    try process_operations(allocator, state, block);
}

// fill this up when we have signature scheme
pub fn verify_signatures(signedBlock: types.SignedBeamBlock) !void {
    _ = signedBlock;
}

// TODO(gballet) check if beam block needs to be a pointer
pub fn apply_transition(allocator: Allocator, state: *types.BeamState, signedBlock: types.SignedBeamBlock, opts: StateTransitionOpts) !void {
    // _ = opts;
    var logger = getLogger();
    logger.setActiveLevel(opts.activeLogLevel);
    const block = signedBlock.message;
    logger.debug("apply transition stateslot={d} blockslot={d}\n", .{ state.slot, block.slot });

    if (block.slot <= state.slot) {
        logger.debug("slots are invalid for block {any}: {} >= {}\n", .{ block, block.slot, state.slot });
        return StateTransitionError.InvalidPreState;
    }

    // verify the proposer and attestation signatures on signed block
    try verify_signatures(signedBlock);

    // prepare the pre state for this block slot
    try process_slots(allocator, state, block.slot);

    // process the block
    try process_block(allocator, state, block);

    // verify the post state root
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, state.*, &state_root, allocator);
    if (!std.mem.eql(u8, &state_root, &block.state_root)) {
        logger.debug("state root={x:02} block root={x:02}\n", .{ state_root, block.state_root });
        return StateTransitionError.InvalidPostState;
    }
}

pub const StateTransitionError = error{
    InvalidParentRoot,
    InvalidPreState,
    InvalidPostState,
    InvalidExecutionPayloadHeaderTimestamp,
    InvalidJustifiableSlot,
    InvalidValidatorId,
};
