const std = @import("std");
const types = @import("zeam-types");
const proving_manager = @import("zeam-state-proving-manager");
const simargs = @import("simargs");
const utils = @import("zeam-state-transition").utils;
const ssz = @import("ssz");

const ZeamArgs = struct {
    zkvm: @TypeOf(proving_manager.available_zkvms) = .Powdr,

    pub const __shorts__ = .{
        .zkvm = .z,
    };

    pub const __messages__ = .{
        .zkvm = "zkvm prover to use",
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const opts = simargs.parse(gpa.allocator(), ZeamArgs, "", "0.0.0");

    if (opts.zkvm != .Powdr) {
        return error.OnlyPowdrProvingIsSupported;
    }

    // Still not the final version, this is just meant to check
    // that the prover is working. Produce + prove 3 blocks.
    const chain_config = types.GenesisSpec{ .genesis_time = (try std.time.Instant.now()).timestamp };
    const genesis_state = try utils.genGenesisState(gpa.allocator(), chain_config);
    var genesis_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, genesis_state, &genesis_root, gpa.allocator());
    const genesis_block = try utils.genGenesisBlock(gpa.allocator(), genesis_state);
    var genesis_block_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, genesis_block, &genesis_block_root, gpa.allocator());

    var last_parent_root: *[32]u8 = &genesis_block_root;

    for (1..3) |i| {
        const block = types.BeamBlock{
            .slot = i,
            .proposer_index = 1,
            .parent_root = last_parent_root.*,
            .state_root = undefined,
            .body = types.BeamBlockBody{},
        };
        const proof = proving_manager.execute_transition(types.BeamState{}, block, .{});
        last_parent_root.* = block;
        proving_manager.verify_transition(proof, types.BeamState{}, proof, .{});
    }
}
