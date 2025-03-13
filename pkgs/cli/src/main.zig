const std = @import("std");
const simargs = @import("simargs");

const types = @import("@zeam/types");
const nodeLib = @import("@zeam/node");
const Clock = nodeLib.Clock;
const stateProvingManager = @import("@zeam/state-proving-manager");

const ZeamArgs = struct {
    genesis: ?u64,

    __commands__: union(enum) {
        clock: struct {},
        prove: struct {
            dist_dir: []const u8 = "zig-out/bin",

            pub const __shorts__ = .{
                .dist_dir = .d,
            };

            pub const __messages__ = .{
                .dist_dir = "Directory where the zkvm guest programs are found",
            };
        },
    },

    pub const __messages__ = .{
        .genesis = "genesis time",
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const opts = try simargs.parse(allocator, ZeamArgs, "", "0.0.0");
    const genesis = opts.args.genesis orelse 1234;
    std.debug.print("opts ={any} genesis={d}\n", .{ opts, genesis });

    switch (opts.args.__commands__) {
        .clock => {
            var clock = try Clock.init(genesis);
            std.debug.print("clock {any}\n", .{clock});

            try clock.run();
        },
        .prove => |provecmd| {
            const state = types.BeamState{
                .genesis_time = 0,
                .slot = 0,
                .latest_block_header = .{
                    .slot = 0,
                    .proposer_index = 0,
                    .parent_root = [_]u8{0} ** 32,
                    .state_root = [_]u8{0} ** 32,
                    .body_root = [_]u8{0} ** 32,
                },
            };
            const block = types.SignedBeamBlock{
                .message = .{
                    .slot = 0,
                    .proposer_index = 0,
                    .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
                    .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
                    .body = .{},
                },
                .signature = [_]u8{0} ** 48,
            };
            std.debug.print("distribution dir={s}\n", .{provecmd.dist_dir});
            const options = stateProvingManager.StateTransitionOpts{
                .zk_vm = stateProvingManager.zkvm_configs[0],
            };

            _ = try stateProvingManager.prove_transition(state, block, options, allocator);
        },
    }
}
