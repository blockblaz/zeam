const std = @import("std");
const ssz = @import("ssz");
const types = @import("@zeam/types");
const state_transition = @import("@zeam/state-transition");
const Allocator = std.mem.Allocator;

pub const ZKVMContext = struct {
    program_path: []const u8,
    output_dir: []const u8,
    backend: ?[]const u8 = null,
};

extern fn powdr_prove(serialized: [*]const u8, len: usize, output: [*]u8, output_len: usize, binary_path: [*]const u8, binary_path_length: usize, result_path: [*]const u8, result_path_len: usize) void;

pub const zkvm_configs: []const ZKVMContext = &.{
    .{ .program_path = "zig-out/bin/zeam-stf-powdr", .output_dir = "out", .backend = "plonky3" },
};

pub const StateTransitionOpts = struct {
    zk_vm: ZKVMContext,
};

pub fn prove_transition(state: types.BeamState, block: types.SignedBeamBlock, opts: StateTransitionOpts, allocator: Allocator) !types.BeamSTFProof {
    _ = opts;
    const prover_input = types.BeamSTFProverInput{
        .state = state,
        .block = block,
    };

    var serialized = std.ArrayList(u8).init(allocator);
    defer serialized.deinit();
    try ssz.serialize(types.BeamSTFProverInput, prover_input, &serialized);

    var output: [256]u8 = undefined;
    powdr_prove(serialized.items.ptr, serialized.items.len, @ptrCast(&output), 256, zkvm_configs[0].program_path.ptr, zkvm_configs[0].program_path.len, zkvm_configs[0].output_dir.ptr, zkvm_configs[0].output_dir.len);
    return types.BeamSTFProof{};
}

pub fn verify_transition(stf_proof: types.BeamSTFProof, state_root: types.Bytes32, block_root: types.Bytes32, opts: StateTransitionOpts) !void {
    _ = stf_proof;
    _ = state_root;
    _ = block_root;
    _ = opts;
}
