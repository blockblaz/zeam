const std = @import("std");
const types = @import("types");
const state_transition = @import("state-transition");
const allocator = std.heap.page_allocator;

pub const ZKVMContext = struct {
    program_path: []const u8,
    output_dir: []const u8,
    backend: []const u8,
};

pub const zkvm_configs: []ZKVMContext = .{
    .{ .program_path = "dist/powdr/zeam-stf.asm", .output_dir = "out", .backend = "plonky3" },
};

const StateTransitionOpts = struct {
    zk_vm: ZKVMContext,
};

pub fn execute_transition(state: types.BeamState, block: types.SignedBeamBlock, opts: StateTransitionOpts) types.BeamSTFProof {
    var publics = std.ArrayList(u8).init(allocator);

    // Run the executable without proving, in order to recover the publics
    var dryrun_process = std.process.Child.init(&[_][]const u8{
        "powdr-rs",
        "execute",
        opts.zk_vm.program_path,
    }, allocator);
    defer dryrun_process.deinit();
    try dryrun_process.env_map.?.put("RUSTi_LOG", "debug");

    dryrun_process.stdout_behavior = .Pipe;
    try dryrun_process.spawn();
    const stdout_stream = dryrun_process.stdout.?;
    const output = try stdout_stream.readToEndAlloc(allocator, 1024 * 100);
    try dryrun_process.wait();

    var lines = std.mem.split(u8, output, "\n");
    while (lines.next()) |line| {
        const start_index = std.mem.indexOf(u8, line, "limb=");
        if (start_index) |idx| {
            if (publics.len != 0) {
                publics.append(',');
            }
            publics.appendSlice(line[idx + 5 ..]);
        }
    }

    // Proving
    var prover_process = std.process.Child.init(&[_][]const u8{
        "powdr",
        "pil",
        opts.zk_vm.program_path,
        "--prove-with",
        opts.zk_vm.backend,
        "-f",
        "-o",
        opts.zk_vm.output_dir,
    }, allocator);
    defer prover_process.deinit();

    prover_process.stdout_behavior = .Inherit;
    prover_process.stderr_behavior = .Inherit;

    try prover_process.spawn();
    var term = try prover_process.wait();
    switch (term) {
        .Exited => |code| if (code != 0) return error.DidNotVerify,
        else => return error.DidNotVerify,
    }

    // Create verification key
    var verification_key_process = std.process.Child.init(&[_][]const u8{
        "powdr",
        "verification-key",
        opts.zk_vm.program_path,
        "--backend",
        opts.zk_vm.backend,
        "-d",
        opts.zk_vm.output_dir,
    }, allocator);
    defer verification_key_process.deinit();

    verification_key_process.stdout_behavior = .Inherit;
    verification_key_process.stderr_behavior = .Inherit;

    try verification_key_process.spawn();
    term = try verification_key_process.wait();
    switch (term) {
        .Exited => |code| if (code != 0) return error.VerificationKeyGenerationError,
        else => return error.VerificationKeyGenerationError,
    }

    // Serialize the proof into some arbitrary format

    return types.BeamSTFProof{
        .zk_vm = .powdr,
        // .proof = ,
        .publics = publics.items,
    };
}

pub fn verify_transition(stf_proof: types.BeamSTFProof, state_root: types.Bytes32, block_root: types.Bytes32, opts: StateTransitionOpts) !void {
    // TODO deserialize proof and set it as parameters

    var process = std.process.Child.init(&[_][]const u8{
        "powdr",
        "verify",
        opts.zk_vm.program_path,
        "--vkey",
        std.fmt.allocPrint(allocator, "{}/vkey.bin", .{opts.zk_vm.output_dir}),
        "--proof",
        std.fmt.allocPrint(allocator, "{}/chunk_0/zeam-poc_proof.bin", .{opts.zk_vm.output_dir}),
        "--publics",
        stf_proof.publics,
        "--backend",
        opts.zk_vm.backend,
        "-d",
        opts.zk_vm.output_dir,
    }, allocator);
    defer process.deinit();

    process.stdout_behavior = .Inherit;
    process.stderr_behavior = .Inherit;

    try process.spawn();
    const term = try process.wait();
    switch (term) {
        .Exited => |code| if (code != 0) return error.DidNotVerify,
        else => return error.DidNotVerify,
    }
}
