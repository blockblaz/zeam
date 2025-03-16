const std = @import("std");
const simargs = @import("simargs");

const types = @import("zeam-types");
const nodeLib = @import("zeam-node");
const Clock = nodeLib.Clock;

const ZeamArgs = struct {
    genesis: ?u64,

    __commands__: union(enum) { clock: struct {} },

    pub const __messages__ = .{
        .genesis = "genesis time",
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const opts = try simargs.parse(gpa.allocator(), ZeamArgs, "", "0.0.0");
    const genesis = opts.args.genesis orelse 1234;
    std.debug.print("opts ={any} genesis={d}\n", .{ opts, genesis });

    switch (opts.args.__commands__) {
        .clock => {
            var clock = try Clock.init(genesis);
            std.debug.print("clock {any}\n", .{clock});

            clock.start();
            try clock.run();
        },
    }
}
