const std = @import("std");
const zbench = @import("zbench");

fn benchAddU64(_: std.mem.Allocator) void {
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < 1024) : (i += 1) sum +%= i;
    std.mem.doNotOptimizeAway(sum);
}

pub fn main(init: std.process.Init) !void {
    _ = init;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    try bench.add("add_u64_x1024", benchAddU64, .{});

    const io = std.Io.Threaded.global_single_threaded.io();
    const stdout = std.Io.File.stdout();
    try bench.run(io, stdout);
}
