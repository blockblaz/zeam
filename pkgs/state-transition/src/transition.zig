const ssz = @import("ssz");
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");
pub const utils = @import("./utils.zig");
const params = @import("@zeam/params");

fn log(comptime fmt: []const u8, args: anytype) !void {
    if (builtin.target.os.tag == .freestanding) {
        const io = @import("zkvm").io;
        var buf: [512]u8 = undefined;
        io.print_str(try std.fmt.bufPrint(buf[0..], fmt, args));
    } else {
        std.debug.print(fmt, args);
    }
}

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

fn process_block_header(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock) !void {
    // very basic process block header
    if (state.slot != block.slot) {
        log("state slot={} block slot={}", .{ state.slot, block.slot }) catch @panic("error printing invalid block slot");
        return StateTransitionError.InvalidPreState;
    }

    var head_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlockHeader, state.latest_block_header, &head_root, allocator);
    if (!std.mem.eql(u8, &head_root, &block.parent_root)) {
        log("state root={any} block root={any}", .{ head_root, block.parent_root }) catch @panic("error printing invalid parent root");
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

pub fn process_block(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock) !void {
    // start block processing
    try process_block_header(allocator, state, block);
    try process_execution_payload_header(state, block);
}

// fill this up when we have signature scheme
pub fn verify_signatures(signedBlock: types.SignedBeamBlock) !void {
    _ = signedBlock;
}

// TODO(gballet) check if beam block needs to be a pointer
pub fn apply_transition(allocator: Allocator, state: *types.BeamState, signedBlock: types.SignedBeamBlock) !void {
    const block = signedBlock.message;
    if (block.slot <= state.slot) {
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
        log("state root={any} block root={any}", .{ state_root, block.state_root }) catch @panic("error printing invalid block root");
        return StateTransitionError.InvalidPostState;
    }
}

pub const StateTransitionError = error{
    InvalidParentRoot,
    InvalidPreState,
    InvalidPostState,
    InvalidExecutionPayloadHeaderTimestamp,
};
