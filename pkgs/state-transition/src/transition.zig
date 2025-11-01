const ssz = @import("ssz");
const std = @import("std");
const json = std.json;
const types = @import("@zeam/types");

const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");

const Allocator = std.mem.Allocator;
const debugLog = zeam_utils.zeamLog;
const StateTransitionError = types.StateTransitionError;

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

// not active in PQ devnet0 - zig will automatically prune this from code
fn process_execution_payload_header(state: *types.BeamState, block: types.BeamBlock) !void {
    const expected_timestamp = state.genesis_time + block.slot * params.SECONDS_PER_SLOT;
    if (expected_timestamp != block.body.execution_payload_header.timestamp) {
        return StateTransitionError.InvalidExecutionPayloadHeaderTimestamp;
    }
}

pub fn apply_raw_block(allocator: Allocator, state: *types.BeamState, block: *types.BeamBlock, logger: zeam_utils.ModuleLogger) !void {
    // prepare pre state to process block for that slot, may be rename prepare_pre_state
    try state.process_slots(allocator, block.slot, logger);

    // process block and modify the pre state to post state
    try state.process_block(allocator, block.*, logger);

    logger.debug("extracting state root\n", .{});
    // extract the post state root
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(*types.BeamState, state, &state_root, allocator);
    block.state_root = state_root;
}

// fill this up when we have signature scheme
pub fn verify_signatures(signedBlock: types.SignedBlockWithAttestation) !void {
    _ = signedBlock;
}

// TODO(gballet) check if beam block needs to be a pointer
pub fn apply_transition(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, opts: StateTransitionOpts) !void {
    opts.logger.debug("applying  state transition state-slot={d} block-slot={d}\n", .{ state.slot, block.slot });

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
        try ssz.hashTreeRoot(*types.BeamState, state, &state_root, allocator);
        if (!std.mem.eql(u8, &state_root, &block.state_root)) {
            opts.logger.debug("state root={x:02} block root={x:02}\n", .{ state_root, block.state_root });
            return StateTransitionError.InvalidPostState;
        }
    }
}
