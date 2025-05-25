const std = @import("std");
const ssz = @import("ssz");
const types = @import("@zeam/types");
const state_transition = @import("@zeam/state-transition");
const Allocator = std.mem.Allocator;

extern fn powdr_prove(serialized: [*]const u8, len: usize, output: [*]u8, output_len: usize, binary_path: [*]const u8, binary_path_length: usize, result_path: [*]const u8, result_path_len: usize) u32;
extern fn risc0_prove(serialized: [*]const u8, len: usize, binary_path: [*]const u8, binary_path_length: usize, output: [*]u8, output_len: usize) u32;
extern fn risc0_verify(binary_path: *const u8, binary_path_len: usize, receipt: *const u8, receipt_len: usize) bool;

const PowdrConfig = struct {
    program_path: []const u8,
    output_dir: []const u8,
    backend: ?[]const u8 = null,
};

const Risc0Config = struct {
    program_path: []const u8,
};

pub const StateTransitionOpts = union(enum) {
    powdr: PowdrConfig,
    risc0: Risc0Config,
};

pub fn prove_transition(state: types.BeamState, block: types.SignedBeamBlock, opts: StateTransitionOpts, allocator: Allocator) !types.BeamSTFProof {
    const prover_input = types.BeamSTFProverInput{
        .state = state,
        .block = block,
    };

    var serialized = std.ArrayList(u8).init(allocator);
    defer serialized.deinit();
    try ssz.serialize(types.BeamSTFProverInput, prover_input, &serialized);

    var output: [256]u8 = undefined;
    switch (opts) {
        .powdr => |powdrcfg| powdr_prove(serialized.items.ptr, serialized.items.len, @ptrCast(&output), 256, powdrcfg.program_path.ptr, powdrcfg.program_path.len, powdrcfg.output_dir.ptr, powdrcfg.output_dir.len),
        .risc0 => |risc0cfg| risc0_prove(serialized.items.ptr, serialized.items.len, risc0cfg.program_path.ptr, risc0cfg.program_path.len, @ptrCast(&output), 256),
    }
    return types.BeamSTFProof{};
}

pub fn verify_transition(stf_proof: types.BeamSTFProof, state_root: types.Bytes32, block_root: types.Bytes32, opts: StateTransitionOpts) !void {
    _ = state_root;
    _ = block_root;

    const valid = switch (opts) {
        else => return error.UnsupportedVerifier,
    };

    if (!valid) return error.ProofDidNotVerify;
}
