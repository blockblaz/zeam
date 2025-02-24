const ssz = @import("ssz");
const std = @import("std");
const types = @import("zeam-types");

pub const utils = @import("./utils.zig");

// setup a params repo sensitive to a preset
const SLOTS_PER_EPOCH = 32;

// pub fn process_epoch(state: types.BeamState) void {
//     // right now nothing to do
//     _ = state;
//     return;
// }

// prepare the state to be the post-state of the slot
pub fn process_slot(state: types.BeamState) void {

    // update state root in latest block header if its zero hash
    // i.e. just after processing the lastest block of latest block header
    // this completes latest block header for parentRoot checks of new block
    if (std.mem.eql(state.lastest_block_header.state_root, utils.ZERO_HASH)) {
        const prev_state_root = ssz.hash_tree_root(state);
        state.lastest_block_header.state_root = prev_state_root;
    }
}

// prepare the state to be pre state of the slot
pub fn process_slots(state: types.BeamState, slot: types.Slot) void {
    while (state.slot < slot) {
        process_slot(state);
        // There might not be epoch processing in beam
        // if ((state.slot + 1) % SLOTS_PER_EPOCH == 0) {
        //     process_epoch(state);
        // }

        state.slot += 1;
    }
}

fn process_block_header(state: types.BeamState, block: types.BeamBlock) !void {
    // very basic process block header
    if (state.slot != block.slot) {
        return StateTransitionError.InvalidPreState;
    }

    const headHash = ssz.tree_root_hash(state.lastest_block_header);
    if (!std.mem.eql(headHash, block.message.parent_root)) {
        return StateTransitionError.InvalidParentRoot;
    }

    state.lastest_block_header = utils.blockToLatestBlockHeader(block.message);
}

pub fn apply_transition(state: types.BeamState, block: types.SignedBeamBlock) !void {
    // prepare the pre state for this block slot
    process_slots(state, block.slot);

    // start block processing
    try process_block_header(state, block);
}

const StateTransitionError = error{
    InvalidPreState,
    InvalidParentRoot,
};

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}
