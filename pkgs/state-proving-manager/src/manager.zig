const std = @import("std");
const json = std.json;
const ssz = @import("ssz");
const types = @import("@zeam/types");
const state_transition = @import("@zeam/state-transition");
const utils = @import("@zeam/utils");
const jsonToString = utils.jsonToString;
const build_options = @import("build_options");

const Allocator = std.mem.Allocator;

// extern fn powdr_prove(serialized: [*]const u8, len: usize, output: [*]u8, output_len: usize, binary_path: [*]const u8, binary_path_length: usize, result_path: [*]const u8, result_path_len: usize) u32;

// Conditionally declare extern functions - these will only be linked if the library is included
extern fn risc0_prove(serialized: [*]const u8, len: usize, binary_path: [*]const u8, binary_path_length: usize, output: [*]u8, output_len: usize) callconv(.C) u32;
extern fn risc0_verify(binary_path: [*]const u8, binary_path_len: usize, receipt: [*]const u8, receipt_len: usize) callconv(.C) bool;

fn risc0_prove_stub(serialized: [*]const u8, len: usize, binary_path: [*]const u8, binary_path_length: usize, output: [*]u8, output_len: usize) u32 {
    _ = serialized;
    _ = len;
    _ = binary_path;
    _ = binary_path_length;
    _ = output;
    _ = output_len;
    @panic("RISC0 support not compiled in");
}

fn risc0_verify_stub(binary_path: [*]const u8, binary_path_len: usize, receipt: [*]const u8, receipt_len: usize) bool {
    _ = binary_path;
    _ = binary_path_len;
    _ = receipt;
    _ = receipt_len;
    @panic("RISC0 support not compiled in");
}

const risc0_prove_fn = if (build_options.has_risc0) risc0_prove else risc0_prove_stub;
const risc0_verify_fn = if (build_options.has_risc0) risc0_verify else risc0_verify_stub;

// Conditionally declare extern functions - these will only be linked if the library is included
extern fn openvm_prove(serialized: [*]const u8, len: usize, output: [*]u8, output_len: usize, binary_path: [*]const u8, binary_path_length: usize, result_path: [*]const u8, result_path_len: usize) callconv(.C) u32;
extern fn openvm_verify(binary_path: [*]const u8, binary_path_len: usize, receipt: [*]const u8, receipt_len: usize) callconv(.C) bool;

fn openvm_prove_stub(serialized: [*]const u8, len: usize, output: [*]u8, output_len: usize, binary_path: [*]const u8, binary_path_length: usize, result_path: [*]const u8, result_path_len: usize) u32 {
    _ = serialized;
    _ = len;
    _ = output;
    _ = output_len;
    _ = binary_path;
    _ = binary_path_length;
    _ = result_path;
    _ = result_path_len;
    @panic("OpenVM support not compiled in");
}

fn openvm_verify_stub(binary_path: [*]const u8, binary_path_len: usize, receipt: [*]const u8, receipt_len: usize) bool {
    _ = binary_path;
    _ = binary_path_len;
    _ = receipt;
    _ = receipt_len;
    @panic("OpenVM support not compiled in");
}

const openvm_prove_fn = if (build_options.has_openvm) openvm_prove else openvm_prove_stub;
const openvm_verify_fn = if (build_options.has_openvm) openvm_verify else openvm_verify_stub;

const PowdrConfig = struct {
    program_path: []const u8,
    output_dir: []const u8,
    backend: ?[]const u8 = null,
};

const Risc0Config = struct {
    program_path: []const u8,
};

const OpenVMConfig = struct {
    program_path: []const u8,
    result_path: []const u8,
};

const ZKVMConfig = union(enum) {
    powdr: PowdrConfig,
    risc0: Risc0Config,
    openvm: OpenVMConfig,
};
pub const ZKVMs = std.meta.Tag(ZKVMConfig);

const ZKVMOpts = struct { zkvm: ZKVMConfig };

pub const ZKStateTransitionOpts = utils.MixIn(state_transition.StateTransitionOpts, ZKVMOpts);

pub fn prove_transition(state: types.BeamState, block: types.BeamBlock, opts: ZKStateTransitionOpts, allocator: Allocator) !types.BeamSTFProof {
    // TODO:  we should also serialize StateTransitionOpts from ZKStateTransitionOpts and feed it to apply
    // transition in the guest program. it makes sense if opts in future will also carry flags like signatures
    // validated. Even logging opts would change the execution trace and hence the proof
    const prover_input = types.BeamSTFProverInput{
        .state = state,
        .block = block,
    };

    var serialized = std.ArrayList(u8).init(allocator);
    defer serialized.deinit();
    try ssz.serialize(types.BeamSTFProverInput, prover_input, &serialized);

    opts.logger.debug("prove transition ----------- serialized({d})=\n{any}\n", .{ serialized.items.len, serialized.items });

    var prover_input_deserialized: types.BeamSTFProverInput = undefined;
    try ssz.deserialize(types.BeamSTFProverInput, serialized.items[0..], &prover_input_deserialized, allocator);

    const state_str = try prover_input_deserialized.state.toJsonString(allocator);
    defer allocator.free(state_str);

    opts.logger.debug("should deserialize to={s}", .{state_str});

    // allocate a megabyte of data so that we have enough space for the proof.
    // XXX not deallocated yet
    var output = try allocator.alloc(u8, 1024 * 1024);
    const output_len = switch (opts.zkvm) {
        // .powdr => |powdrcfg| powdr_prove(serialized.items.ptr, serialized.items.len, @ptrCast(&output), 256, powdrcfg.program_path.ptr, powdrcfg.program_path.len, powdrcfg.output_dir.ptr, powdrcfg.output_dir.len),
        .powdr => return error.RiscVPowdrIsDeprecated,
        .risc0 => |risc0cfg| risc0_prove_fn(serialized.items.ptr, serialized.items.len, risc0cfg.program_path.ptr, risc0cfg.program_path.len, output.ptr, output.len),
        .openvm => |openvmcfg| openvm_prove_fn(serialized.items.ptr, serialized.items.len, output.ptr, output.len, openvmcfg.program_path.ptr, openvmcfg.program_path.len, openvmcfg.result_path.ptr, openvmcfg.result_path.len),
        // else => @panic("prover isn't enabled"),
    };
    const proof = types.BeamSTFProof{
        .proof = output[0..output_len],
    };
    opts.logger.debug("proof len={}\n", .{output_len});

    return proof;
}

pub fn verify_transition(stf_proof: types.BeamSTFProof, state_root: types.Bytes32, block_root: types.Bytes32, opts: ZKStateTransitionOpts) !void {
    _ = state_root;
    _ = block_root;

    const valid = switch (opts.zkvm) {
        .risc0 => |risc0cfg| risc0_verify_fn(risc0cfg.program_path.ptr, risc0cfg.program_path.len, stf_proof.proof.ptr, stf_proof.proof.len),
        .openvm => |openvmcfg| openvm_verify_fn(openvmcfg.program_path.ptr, openvmcfg.program_path.len, stf_proof.proof.ptr, stf_proof.proof.len),
        else => return error.UnsupportedVerifier,
    };

    if (!valid) return error.ProofDidNotVerify;
}
