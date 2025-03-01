const Builder = @import("std").Build;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // add ssz
    const ssz = b.dependency("ssz.zig", .{
        .target = target,
        .optimize = optimize,
    }).module("ssz.zig");
    // add zeam-types
    const zeam_types = b.dependency("zeam-types", .{
        .target = target,
        .optimize = optimize,
    }).module("zeam-types");
    // add state transition
    const zeam_state_transition = b.dependency("zeam-state-transition", .{
        .target = target,
        .optimize = optimize,
    }).module("zeam-state-transition");
    // add state transition manager
    const zeam_state_proving_manager = b.dependency("zeam-state-proving-manager", .{
        .target = target,
        .optimize = optimize,
    }).module("zeam-state-proving-manager");

    const mod = b.addModule("zeam-beam-node", Builder.Module.CreateOptions{
        .root_source_file = b.path("src/node.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ssz", .module = ssz },
            .{ .name = "zeam-types", .module = zeam_types },
            .{ .name = "zeam-state-transition", .module = zeam_state_transition },
            .{ .name = "zeam-state-proving-manager", .module = zeam_state_proving_manager },
        },
    });
    _ = mod;

    const lib = b.addStaticLibrary(.{
        .name = "zeam-beam-node",
        .root_source_file = .{ .cwd_relative = "src/node.zig" },
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(lib);

    const tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/node.zig" },
        .optimize = optimize,
        .target = target,
    });
    tests.root_module.addImport("ssz", ssz);
    tests.root_module.addImport("zeam-types", zeam_types);
    tests.root_module.addImport("zeam-state-transition", zeam_state_transition);
    tests.root_module.addImport("zeam-state-proving-manager", zeam_state_proving_manager);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
