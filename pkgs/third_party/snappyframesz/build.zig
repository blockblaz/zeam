const Builder = @import("std").Build;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const snappyz = b.dependency("snappyz", .{
        .target = target,
        .optimize = optimize,
    }).module("snappyz");

    const mod = b.addModule("snappyframesz.zig", .{
        .root_source_file = b.path("src/frames.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "snappyz", .module = snappyz },
        },
    });

    const lib = b.addLibrary(.{
        .name = "snappyframesz",
        .root_module = mod,
    });
    b.installArtifact(lib);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/frames.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "snappyz", .module = snappyz },
            },
        }),
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
