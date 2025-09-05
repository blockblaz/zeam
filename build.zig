const std = @import("std");
const builtin = @import("builtin");
const Builder = std.Build;

const zkvmTarget = struct {
    name: []const u8,
    set_pie: bool = false,
    triplet: []const u8,
    cpu_features: []const u8,
};

const zkvm_targets: []const zkvmTarget = &.{
    .{ .name = "risc0", .triplet = "riscv32-freestanding-none", .cpu_features = "generic_rv32" },
    .{ .name = "zisk", .set_pie = true, .triplet = "riscv64-freestanding-none", .cpu_features = "generic_rv64" },
};

// Add the glue libs to a compile target
fn addRustGlueLib(b: *Builder, comp: *Builder.Step.Compile, target: Builder.ResolvedTarget) void {
    comp.addObjectFile(b.path("rust/target/release/librustglue.a"));
    // Add macOS framework linking for CLI tests
    if (target.result.os.tag == .macos) {
        comp.linkFramework("CoreFoundation");
        comp.linkFramework("SystemConfiguration");
    }
}

pub fn build(b: *Builder) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get git commit hash as version
    const git_version = b.option([]const u8, "git_version", "Git commit hash for version") orelse "unknown";

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
    const metrics = b.dependency("metrics", .{
        .target = target,
        .optimize = optimize,
    }).module("metrics");

    const datetime = b.dependency("datetime", .{
        .target = target,
        .optimize = optimize,
    }).module("datetime");

    // add zeam-utils
    const zeam_utils = b.addModule("@zeam/utils", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/utils/src/lib.zig"),
    });
    zeam_utils.addImport("datetime", datetime);

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
    zeam_types.addImport("ssz", ssz);
    zeam_types.addImport("@zeam/params", zeam_params);

    // add zeam-types
    const zeam_configs = b.addModule("@zeam/configs", .{
        .root_source_file = b.path("pkgs/configs/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeam_configs.addImport("@zeam/utils", zeam_utils);
    zeam_configs.addImport("@zeam/types", zeam_types);
    zeam_configs.addImport("@zeam/params", zeam_params);

    // add zeam-metrics
    const zeam_metrics = b.addModule("@zeam/metrics", .{
        .root_source_file = b.path("pkgs/metrics/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeam_metrics.addImport("metrics", metrics);

    // add zeam-state-transition
    const zeam_state_transition = b.addModule("@zeam/state-transition", .{
        .root_source_file = b.path("pkgs/state-transition/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeam_state_transition.addImport("@zeam/utils", zeam_utils);
    zeam_state_transition.addImport("@zeam/params", zeam_params);
    zeam_state_transition.addImport("@zeam/types", zeam_types);
    zeam_state_transition.addImport("ssz", ssz);
    zeam_state_transition.addImport("@zeam/metrics", zeam_metrics);

    // add state proving manager
    const zeam_state_proving_manager = b.addModule("@zeam/state-proving-manager", .{
        .root_source_file = b.path("pkgs/state-proving-manager/src/manager.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeam_state_proving_manager.addImport("@zeam/types", zeam_types);
    zeam_state_proving_manager.addImport("@zeam/utils", zeam_utils);
    zeam_state_proving_manager.addImport("@zeam/state-transition", zeam_state_transition);
    zeam_state_proving_manager.addImport("ssz", ssz);

    const st_lib = b.addStaticLibrary(.{
        .name = "zeam-state-transition",
        .root_source_file = b.path("pkgs/state-transition/src/lib.zig"),
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(st_lib);

    // add network
    const zeam_network = b.addModule("@zeam/network", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/network/src/lib.zig"),
    });
    zeam_network.addImport("@zeam/types", zeam_types);
    zeam_network.addImport("xev", xev);
    zeam_network.addImport("ssz", ssz);

    // add beam node
    const zeam_beam_node = b.addModule("@zeam/node", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/node/src/lib.zig"),
    });
    zeam_beam_node.addImport("xev", xev);
    zeam_beam_node.addImport("ssz", ssz);
    zeam_beam_node.addImport("@zeam/utils", zeam_utils);
    zeam_beam_node.addImport("@zeam/params", zeam_params);
    zeam_beam_node.addImport("@zeam/types", zeam_types);
    zeam_beam_node.addImport("@zeam/configs", zeam_configs);
    zeam_beam_node.addImport("@zeam/state-transition", zeam_state_transition);
    zeam_beam_node.addImport("@zeam/network", zeam_network);
    zeam_beam_node.addImport("@zeam/metrics", zeam_metrics);

    // Create build options
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", git_version);

    // Add the cli executable
    const cli_exe = b.addExecutable(.{
        .name = "zeam",
        .root_source_file = b.path("pkgs/cli/src/main.zig"),
        .optimize = optimize,
        .target = target,
    });
    // addimport to root module is even required afer declaring it in mod
    cli_exe.root_module.addImport("ssz", ssz);
    cli_exe.root_module.addImport("build_options", build_options.createModule());
    cli_exe.root_module.addImport("simargs", zigcli.module("simargs"));
    cli_exe.root_module.addImport("xev", xev);
    cli_exe.root_module.addImport("@zeam/utils", zeam_utils);
    cli_exe.root_module.addImport("@zeam/params", zeam_params);
    cli_exe.root_module.addImport("@zeam/types", zeam_types);
    cli_exe.root_module.addImport("@zeam/configs", zeam_configs);
    cli_exe.root_module.addImport("@zeam/state-transition", zeam_state_transition);
    cli_exe.root_module.addImport("@zeam/state-proving-manager", zeam_state_proving_manager);
    cli_exe.root_module.addImport("@zeam/network", zeam_network);
    cli_exe.root_module.addImport("@zeam/node", zeam_beam_node);
    cli_exe.root_module.addImport("@zeam/metrics", zeam_metrics);
    cli_exe.root_module.addImport("metrics", metrics);

    addRustGlueLib(b, cli_exe, target);
    cli_exe.linkLibC(); // for rust static libs to link
    cli_exe.linkSystemLibrary("unwind"); // to be able to display rust backtraces

    b.installArtifact(cli_exe);

    try build_zkvm_targets(b, &cli_exe.step, target);

    var zkvm_host_cmd = build_rust_project(b, "rust");
    cli_exe.step.dependOn(&zkvm_host_cmd.step);

    const run_prover = b.addRunArtifact(cli_exe);
    const prover_step = b.step("run", "Run cli executable");
    prover_step.dependOn(&run_prover.step);
    if (b.args) |args| {
        run_prover.addArgs(args);
    } else {
        run_prover.addArgs(&[_][]const u8{"prove"});
        run_prover.addArgs(&[_][]const u8{ "-d", b.fmt("{s}/bin", .{b.install_path}) });
    }

    const test_step = b.step("test", "Run unit tests");

    const types_tests = b.addTest(.{
        .root_module = zeam_types,
        .optimize = optimize,
        .target = target,
    });
    types_tests.root_module.addImport("ssz", ssz);
    const run_types_test = b.addRunArtifact(types_tests);
    test_step.dependOn(&run_types_test.step);

    const transition_tests = b.addTest(.{
        .root_module = zeam_state_transition,
        .optimize = optimize,
        .target = target,
    });
    // TODO(gballet) typing modules each time is quite tedious, hopefully
    // this will no longer be necessary in later versions of zig.
    transition_tests.root_module.addImport("@zeam/types", zeam_types);
    transition_tests.root_module.addImport("@zeam/params", zeam_params);
    transition_tests.root_module.addImport("ssz", ssz);
    const run_transition_test = b.addRunArtifact(transition_tests);
    test_step.dependOn(&run_transition_test.step);

    const manager_tests = b.addTest(.{
        .root_module = zeam_state_proving_manager,
        .optimize = optimize,
        .target = target,
    });
    manager_tests.root_module.addImport("@zeam/types", zeam_types);
    addRustGlueLib(b, manager_tests, target);
    const run_manager_test = b.addRunArtifact(manager_tests);
    test_step.dependOn(&run_manager_test.step);

    const node_tests = b.addTest(.{
        .root_module = zeam_beam_node,
        .optimize = optimize,
        .target = target,
    });
    const run_node_test = b.addRunArtifact(node_tests);
    test_step.dependOn(&run_node_test.step);

    const cli_tests = b.addTest(.{
        .root_module = cli_exe.root_module,
        .optimize = optimize,
        .target = target,
    });
    addRustGlueLib(b, cli_tests, target);
    const run_cli_test = b.addRunArtifact(cli_tests);
    test_step.dependOn(&run_cli_test.step);

    const params_tests = b.addTest(.{
        .root_module = zeam_params,
        .optimize = optimize,
        .target = target,
    });
    const run_params_tests = b.addRunArtifact(params_tests);
    test_step.dependOn(&run_params_tests.step);
    manager_tests.step.dependOn(&zkvm_host_cmd.step);
    cli_tests.step.dependOn(&zkvm_host_cmd.step);
}

fn build_rust_project(b: *Builder, path: []const u8) *Builder.Step.Run {
    return b.addSystemCommand(&.{
        "cargo",
        "+nightly",
        "-C",
        path,
        "-Z",
        "unstable-options",
        "build",
        "--release",
    });
}

fn build_zkvm_targets(b: *Builder, main_exe: *Builder.Step, host_target: std.Build.ResolvedTarget) !void {
    const optimize = .ReleaseFast;

    for (zkvm_targets) |zkvm_target| {
        const target_query = try std.Build.parseTargetQuery(.{ .arch_os_abi = zkvm_target.triplet, .cpu_features = zkvm_target.cpu_features });
        const target = b.resolveTargetQuery(target_query);

        // add ssz
        const ssz = b.dependency("ssz", .{
            .target = target,
            .optimize = optimize,
        }).module("ssz.zig");

        // add zeam-params
        const zeam_params = b.addModule("@zeam/params", .{
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
        zeam_types.addImport("@zeam/params", zeam_params);

        // add zeam-params
        const zeam_utils = b.addModule("@zeam/utils", .{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("pkgs/utils/src/lib.zig"),
        });

        const zkvm_module = b.addModule("zkvm", .{
            .optimize = optimize,
            .target = target,
            .root_source_file = b.path(b.fmt("pkgs/state-transition-runtime/src/{s}/lib.zig", .{zkvm_target.name})),
        });
        zeam_utils.addImport("zkvm", zkvm_module);

        // add state transition, create a new module for each zkvm since
        // that module depends on the zkvm module.
        const zeam_state_transition = b.addModule("@zeam/state-transition", .{
            .root_source_file = b.path("pkgs/state-transition/src/lib.zig"),
            .target = target,
            .optimize = optimize,
        });
        zeam_state_transition.addImport("@zeam/utils", zeam_utils);
        zeam_state_transition.addImport("@zeam/params", zeam_params);
        zeam_state_transition.addImport("@zeam/types", zeam_types);
        zeam_state_transition.addImport("ssz", ssz);
        zeam_state_transition.addImport("zkvm", zkvm_module);

        // target has to be riscv5 runtime provable/verifiable on zkVMs
        var exec_name: [256]u8 = undefined;
        var exe = b.addExecutable(.{
            .name = try std.fmt.bufPrint(&exec_name, "zeam-stf-{s}", .{zkvm_target.name}),
            .root_source_file = b.path("pkgs/state-transition-runtime/src/main.zig"),
            .optimize = optimize,
            .target = target,
        });
        // addimport to root module is even required afer declaring it in mod
        exe.root_module.addImport("ssz", ssz);
        exe.root_module.addImport("@zeam/utils", zeam_utils);
        exe.root_module.addImport("@zeam/params", zeam_params);
        exe.root_module.addImport("@zeam/types", zeam_types);
        exe.root_module.addImport("@zeam/state-transition", zeam_state_transition);
        exe.root_module.addImport("zkvm", zkvm_module);
        exe.addAssemblyFile(b.path(b.fmt("pkgs/state-transition-runtime/src/{s}/start.s", .{zkvm_target.name})));
        if (zkvm_target.set_pie) {
            exe.pie = true;
        }
        exe.setLinkerScript(b.path(b.fmt("pkgs/state-transition-runtime/src/{s}/{s}.ld", .{ zkvm_target.name, zkvm_target.name })));
        main_exe.dependOn(&b.addInstallArtifact(exe, .{}).step);

        // in case of risc0, use an external tool to format the executable
        // the way the executor expects it.
        if (std.mem.eql(u8, zkvm_target.name, "risc0")) {
            const risc0_postbuild_gen = b.addExecutable(.{
                .name = "risc0ospkg",
                .root_source_file = b.path("build/risc0.zig"),
                .target = host_target,
                .optimize = .ReleaseSafe,
            });
            const run_risc0_postbuild_gen_step = b.addRunArtifact(risc0_postbuild_gen);
            run_risc0_postbuild_gen_step.addFileArg(exe.getEmittedBin());
            const install_generated = b.addInstallBinFile(try exe.getEmittedBinDirectory().join(b.allocator, "risc0_runtime.elf"), "risc0_runtime.elf");
            install_generated.step.dependOn(&run_risc0_postbuild_gen_step.step);
            main_exe.dependOn(&install_generated.step);
        }
    }
}
