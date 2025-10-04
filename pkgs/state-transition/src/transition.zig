const ssz = @import("ssz");
const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");
pub const utils = @import("./utils.zig");

const zeam_utils = @import("@zeam/utils");
const debugLog = zeam_utils.zeamLog;
const jsonToString = zeam_utils.jsonToString;

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

    try block.blockToLatestBlockHeader(allocator, &state.latest_block_header);
}

// not active in PQ devnet0 - zig will automatically prune this from code
fn process_execution_payload_header(state: *types.BeamState, block: types.BeamBlock) !void {
    const expected_timestamp = state.genesis_time + block.slot * params.SECONDS_PER_SLOT;
    if (expected_timestamp != block.body.execution_payload_header.timestamp) {
        return StateTransitionError.InvalidExecutionPayloadHeaderTimestamp;
    }
}

fn process_operations(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, logger: zeam_utils.ModuleLogger) !void {
    // 1. process attestations - now using BeamState member function
    try state.processAttestations(allocator, block.body.attestations, logger);
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
