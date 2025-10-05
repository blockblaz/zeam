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
    comp.linkLibC();
    comp.linkSystemLibrary("unwind"); // to be able to display rust backtraces
    // Add macOS framework linking for CLI tests
    if (target.result.os.tag == .macos) {
        comp.linkFramework("CoreFoundation");
        comp.linkFramework("SystemConfiguration");
        comp.linkFramework("Security");
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
    const simargs = b.dependency("zigcli", .{
        .target = target,
        .optimize = optimize,
    }).module("simargs");
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

    const enr_dep = b.dependency("zig_enr", .{
        .target = target,
        .optimize = optimize,
    });
    const enr = enr_dep.module("zig-enr");

    const multiformats = enr_dep.builder.dependency("zmultiformats", .{
        .target = target,
        .optimize = optimize,
    }).module("multiformats-zig");

    const yaml = b.dependency("zig_yaml", .{
        .target = target,
        .optimize = optimize,
    }).module("yaml");

    // add rocksdb
    const rocksdb = b.dependency("rocksdb", .{
        .target = target,
        .optimize = optimize,
    }).module("bindings");

    // add snappyz
    const snappyz = b.dependency("zig_snappy", .{
        .target = target,
        .optimize = optimize,
    }).module("snappyz");

    // add zeam-utils
    const zeam_utils = b.addModule("@zeam/utils", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/utils/src/lib.zig"),
    });
    zeam_utils.addImport("datetime", datetime);
    zeam_utils.addImport("yaml", yaml);

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
    zeam_types.addImport("@zeam/utils", zeam_utils);

    // add zeam-types
    const zeam_configs = b.addModule("@zeam/configs", .{
        .root_source_file = b.path("pkgs/configs/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeam_configs.addImport("@zeam/utils", zeam_utils);
    zeam_configs.addImport("@zeam/types", zeam_types);
    zeam_configs.addImport("@zeam/params", zeam_params);
    zeam_configs.addImport("yaml", yaml);

    // add zeam-metrics
    // Rename metrics module to api (keeps same source path for now)
    const zeam_api = b.addModule("@zeam/api", .{
        .root_source_file = b.path("pkgs/api/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeam_api.addImport("metrics", metrics);
    zeam_api.addImport("@zeam/types", zeam_types);
    zeam_api.addImport("@zeam/utils", zeam_utils);

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
    zeam_state_transition.addImport("@zeam/api", zeam_api);

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

    // add zeam-database
    const zeam_database = b.addModule("@zeam/database", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/database/src/lib.zig"),
    });
    zeam_database.addImport("rocksdb", rocksdb);
    zeam_database.addImport("ssz", ssz);
    zeam_database.addImport("@zeam/utils", zeam_utils);
    zeam_database.addImport("@zeam/types", zeam_types);

    // add network
    const zeam_network = b.addModule("@zeam/network", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/network/src/lib.zig"),
    });
    zeam_network.addImport("@zeam/types", zeam_types);
    zeam_network.addImport("@zeam/utils", zeam_utils);
    zeam_network.addImport("xev", xev);
    zeam_network.addImport("ssz", ssz);
    zeam_network.addImport("multiformats", multiformats);
    zeam_network.addImport("snappyz", snappyz);

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
    zeam_beam_node.addImport("@zeam/database", zeam_database);
    zeam_beam_node.addImport("@zeam/api", zeam_api);

    const zeam_spectests = b.addModule("zeam_spectests", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("pkgs/spectest/src/lib.zig"),
    });
    zeam_spectests.addImport("@zeam/utils", zeam_utils);
    zeam_spectests.addImport("@zeam/types", zeam_types);
    zeam_spectests.addImport("@zeam/configs", zeam_configs);
    zeam_spectests.addImport("@zeam/params", zeam_params);
    zeam_spectests.addImport("ssz", ssz);

    // Create build options
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", git_version);
    const build_options_module = build_options.createModule();

    // Add the cli executable
    const cli_exe = b.addExecutable(.{
        .name = "zeam",
        .root_source_file = b.path("pkgs/cli/src/main.zig"),
        .optimize = optimize,
        .target = target,
    });
    // addimport to root module is even required afer declaring it in mod
    cli_exe.root_module.addImport("ssz", ssz);
    cli_exe.root_module.addImport("build_options", build_options_module);
    cli_exe.root_module.addImport("simargs", simargs);
    cli_exe.root_module.addImport("xev", xev);
    cli_exe.root_module.addImport("@zeam/database", zeam_database);
    cli_exe.root_module.addImport("@zeam/utils", zeam_utils);
    cli_exe.root_module.addImport("@zeam/params", zeam_params);
    cli_exe.root_module.addImport("@zeam/types", zeam_types);
    cli_exe.root_module.addImport("@zeam/configs", zeam_configs);
    cli_exe.root_module.addImport("@zeam/state-transition", zeam_state_transition);
    cli_exe.root_module.addImport("@zeam/state-proving-manager", zeam_state_proving_manager);
    cli_exe.root_module.addImport("@zeam/network", zeam_network);
    cli_exe.root_module.addImport("@zeam/node", zeam_beam_node);
    cli_exe.root_module.addImport("@zeam/api", zeam_api);
    cli_exe.root_module.addImport("metrics", metrics);
    cli_exe.root_module.addImport("multiformats", multiformats);
    cli_exe.root_module.addImport("enr", enr);
    cli_exe.root_module.addImport("yaml", yaml);

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

    const tools_step = b.step("tools", "Build zeam tools");

    const tools_cli_exe = b.addExecutable(.{
        .name = "zeam-tools",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("pkgs/tools/src/main.zig"),
        }),
    });
    tools_cli_exe.root_module.addImport("enr", enr);
    tools_cli_exe.root_module.addImport("build_options", build_options_module);
    tools_cli_exe.root_module.addImport("simargs", simargs);

    const install_tools_cli = b.addInstallArtifact(tools_cli_exe, .{});
    tools_step.dependOn(&install_tools_cli.step);

    const all_step = b.step("all", "Build all executables and tools");
    all_step.dependOn(&cli_exe.step);
    all_step.dependOn(tools_step);

    const test_step = b.step("test", "Run zeam core tests");

    // CLI integration tests (separate target) - always create this test target
    const cli_integration_tests = b.addTest(.{
        .root_source_file = b.path("pkgs/cli/test/integration.zig"),
        .optimize = optimize,
        .target = target,
    });

    const integration_build_options = b.addOptions();
    cli_integration_tests.step.dependOn(&cli_exe.step);
    integration_build_options.addOptionPath("cli_exe_path", cli_exe.getEmittedBin());
    const integration_build_options_module = integration_build_options.createModule();
    cli_integration_tests.root_module.addImport("build_options", integration_build_options_module);

    // Add CLI constants module to integration tests
    const cli_constants = b.addModule("cli_constants", .{
        .root_source_file = b.path("pkgs/cli/src/constants.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_integration_tests.root_module.addImport("cli_constants", cli_constants);

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
    cli_tests.step.dependOn(&cli_exe.step);
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

    const network_tests = b.addTest(.{
        .root_module = zeam_network,
        .optimize = optimize,
        .target = target,
    });
    network_tests.root_module.addImport("@zeam/types", zeam_types);
    network_tests.root_module.addImport("xev", xev);
    network_tests.root_module.addImport("ssz", ssz);
    const run_network_tests = b.addRunArtifact(network_tests);
    test_step.dependOn(&run_network_tests.step);

    const configs_tests = b.addTest(.{
        .root_module = zeam_configs,
        .optimize = optimize,
        .target = target,
    });
    configs_tests.root_module.addImport("@zeam/utils", zeam_utils);
    configs_tests.root_module.addImport("@zeam/types", zeam_types);
    configs_tests.root_module.addImport("@zeam/params", zeam_params);
    configs_tests.root_module.addImport("yaml", yaml);
    const run_configs_tests = b.addRunArtifact(configs_tests);
    test_step.dependOn(&run_configs_tests.step);

    const utils_tests = b.addTest(.{
        .root_module = zeam_utils,
        .optimize = optimize,
        .target = target,
    });
    const run_utils_tests = b.addRunArtifact(utils_tests);
    test_step.dependOn(&run_utils_tests.step);

    const database_tests = b.addTest(.{
        .root_module = zeam_database,
        .optimize = optimize,
        .target = target,
    });
    const run_database_tests = b.addRunArtifact(database_tests);
    test_step.dependOn(&run_database_tests.step);

    const spectests = b.addTest(.{
        .root_module = zeam_spectests,
        .optimize = optimize,
        .target = target,
    });
    spectests.root_module.addImport("@zeam/utils", zeam_utils);
    spectests.root_module.addImport("@zeam/types", zeam_types);
    spectests.root_module.addImport("@zeam/configs", zeam_configs);
    spectests.root_module.addImport("@zeam/state-transition", zeam_state_transition);
    spectests.root_module.addImport("ssz", ssz);

    manager_tests.step.dependOn(&zkvm_host_cmd.step);
    cli_tests.step.dependOn(&zkvm_host_cmd.step);

    const tools_test_step = b.step("test-tools", "Run zeam tools tests");
    const tools_cli_tests = b.addTest(.{
        .root_module = tools_cli_exe.root_module,
        .optimize = optimize,
        .target = target,
    });
    tools_cli_tests.root_module.addImport("enr", enr);
    const run_tools_cli_test = b.addRunArtifact(tools_cli_tests);
    tools_test_step.dependOn(&run_tools_cli_test.step);

    test_step.dependOn(tools_test_step);

    // Create simtest step that runs only integration tests
    const simtests = b.step("simtest", "Run integration tests");
    const run_cli_integration_test = b.addRunArtifact(cli_integration_tests);
    simtests.dependOn(&run_cli_integration_test.step);

    // Create spectest step that runs spec tests
    const spectests_step = b.step("spectest", "Run spec tests");
    const run_spectests = b.addRunArtifact(spectests);
    spectests_step.dependOn(&run_spectests.step);
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

        // add zeam-utils
        const zeam_utils = b.addModule("@zeam/utils", .{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("pkgs/utils/src/lib.zig"),
        });

        // add zeam-types
        const zeam_types = b.addModule("@zeam/types", .{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("pkgs/types/src/lib.zig"),
        });
        zeam_types.addImport("ssz", ssz);
        zeam_types.addImport("@zeam/params", zeam_params);
        zeam_types.addImport("@zeam/utils", zeam_utils);

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
