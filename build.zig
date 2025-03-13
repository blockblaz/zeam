const std = @import("std");
const Builder = std.Build;

const zkvmTarget = struct {
    name: []const u8,
    set_pie: bool = false,
    build_glue: bool = false,
};

const zkvm_targets: []const zkvmTarget = &.{
    .{ .name = "powdr", .set_pie = true, .build_glue = true },
    .{ .name = "ceno", .set_pie = false },
};

pub fn build(b: *Builder) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // add ssz
    const ssz = b.dependency("ssz", .{
        .target = target,
        .optimize = optimize,
    }).module("ssz.zig");
    const zigcli = b.dependency("zigcli", .{
        .target = target,
        .optimize = optimize,
    });
    const xev = b.dependency("xev", .{
        .target = target,
        .optimize = optimize,
    }).module("xev");

    // add zeam-params
    const zeam_params = b.addModule("@zeam/params", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/params/src/lib.zig"),
    });

    // add zeam-types
    const zeam_types = b.addModule("@zeam/types", .{
        .root_source_file = b.path("pkgs/types/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // add zeam-state-transition
    const zeam_state_transition = b.addModule("@zeam/state-transition", .{
        .root_source_file = b.path("pkgs/state-transition/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeam_state_transition.addImport("@zeam/types", zeam_types);
    zeam_state_transition.addImport("ssz", ssz);

    // add state proving manager
    const zeam_state_proving_manager = b.addModule("@zeam/state-proving-manager", .{
        .root_source_file = b.path("pkgs/state-proving-manager/src/manager.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeam_state_proving_manager.addImport("@zeam/types", zeam_types);
    zeam_state_proving_manager.addImport("@zeam/state-transition", zeam_state_transition);
    zeam_state_proving_manager.addImport("ssz", ssz);

    const st_lib = b.addStaticLibrary(.{
        .name = "zeam-state-transition",
        .root_source_file = b.path("pkgs/state-transition/src/lib.zig"),
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(st_lib);

    // add beam node
    const zeam_beam_node = b.addModule("@zeam/node", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/node/src/lib.zig"),
    });
    zeam_beam_node.addImport("xev", xev);
    zeam_beam_node.addImport("@zeam/params", zeam_params);

    // Add the cli executable
    const cli_exe = b.addExecutable(.{
        .name = "zeam",
        .root_source_file = b.path("pkgs/cli/src/main.zig"),
        .optimize = optimize,
        .target = target,
    });
    // addimport to root module is even required afer declaring it in mod
    cli_exe.root_module.addImport("ssz", ssz);
    cli_exe.root_module.addImport("simargs", zigcli.module("simargs"));
    cli_exe.root_module.addImport("xev", xev);
    cli_exe.root_module.addImport("@zeam/types", zeam_types);
    cli_exe.root_module.addImport("@zeam/state-transition", zeam_state_transition);
    cli_exe.root_module.addImport("@zeam/state-proving-manager", zeam_state_proving_manager);
    cli_exe.root_module.addImport("@zeam/node", zeam_beam_node);
    cli_exe.root_module.addImport("@zeam/params", zeam_params);
    for (zkvm_targets) |zkvm_target| {
        if (zkvm_target.build_glue) {
            const zkvm_host_cmd = b.addSystemCommand(&.{
                "cargo",
                "+nightly",
                "-C",
                b.fmt("pkgs/state-transition-runtime/src/{s}/host", .{zkvm_target.name}),
                "-Z",
                "unstable-options",
                "build",
                "--release",
            });
            cli_exe.step.dependOn(&zkvm_host_cmd.step);
            cli_exe.addObjectFile(b.path(b.fmt("pkgs/state-transition-runtime/src/{s}/host/target/release/libzeam_prover_host_{s}.a", .{ zkvm_target.name, zkvm_target.name })));
        }
    }
    cli_exe.linkLibC(); // for rust static libs to link
    cli_exe.linkSystemLibrary("unwind"); // to be able to display rust backtraces
    b.installArtifact(cli_exe);

    const run_prover = b.addRunArtifact(cli_exe);
    const prover_step = b.step("run", "Run cli executable");
    prover_step.dependOn(&run_prover.step);
    if (b.args) |args| {
        run_prover.addArgs(args);
    }
    run_prover.addArgs(&[_][]const u8{ "-d", b.fmt("{s}/bin", .{b.install_path}) });

    try build_zkvm_targets(b, &cli_exe.step);

    const tests = b.addTest(.{
        .root_source_file = b.path("pkgs/tests.zig"),
        .optimize = optimize,
        .target = target,
    });
    tests.root_module.addImport("ssz", ssz);
    tests.root_module.addImport("@zeam/types", zeam_types);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}

fn build_zkvm_targets(b: *Builder, main_exe: *Builder.Step) !void {
    const target_query = try std.Build.parseTargetQuery(.{ .arch_os_abi = "riscv32-freestanding-none", .cpu_features = "generic_rv32" });
    const target = b.resolveTargetQuery(target_query);
    const optimize = .ReleaseFast;

    // add ssz
    const ssz = b.dependency("ssz", .{
        .target = target,
        .optimize = optimize,
    }).module("ssz.zig");

    // add zeam-params
    const params = b.addModule("@zeam/params", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/params/src/lib.zig"),
    });

    // add zeam-types
    const zeam_types = b.addModule("@zeam/types", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/types/src/lib.zig"),
    });

    // add state transition
    const zeam_state_transition = b.addModule("@zeam/state-transition", .{
        .root_source_file = b.path("pkgs/state-transition/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeam_state_transition.addImport("@zeam/types", zeam_types);
    zeam_state_transition.addImport("ssz", ssz);

    for (zkvm_targets) |zkvm_target| {
        const zkvm_module = b.addModule("zkvm", .{
            .optimize = optimize,
            .target = target,
            .root_source_file = b.path(b.fmt("pkgs/state-transition-runtime/src/{s}/lib.zig", .{zkvm_target.name})),
        });

        // target has to be riscv5 runtime provable/verifiable on zkVMs
        var exec_name: [256]u8 = undefined;
        const exe = b.addExecutable(.{
            .name = try std.fmt.bufPrint(&exec_name, "zeam-stf-{s}", .{zkvm_target.name}),
            .root_source_file = b.path("pkgs/state-transition-runtime/src/main.zig"),
            .optimize = optimize,
            .target = target,
        });
        // addimport to root module is even required afer declaring it in mod
        exe.root_module.addImport("ssz", ssz);
        exe.root_module.addImport("@zeam/types", zeam_types);
        exe.root_module.addImport("@zeam/state-transition", zeam_state_transition);
        exe.root_module.addImport("zkvm", zkvm_module);
        exe.root_module.addImport("params", params);
        exe.addAssemblyFile(b.path(b.fmt("pkgs/state-transition-runtime/src/{s}/start.s", .{zkvm_target.name})));
        if (zkvm_target.set_pie) {
            exe.pie = true;
        }
        exe.setLinkerScript(b.path(b.fmt("pkgs/state-transition-runtime/src/{s}/{s}.ld", .{ zkvm_target.name, zkvm_target.name })));
        b.installArtifact(exe);
        main_exe.dependOn(&exe.step);
    }
}
