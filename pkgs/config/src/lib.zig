const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const params = @import("@zeam/params");
const types = @import("@zeam/types");

const configs = @import("./configs/mainnet.zig");

pub const Chain = enum { custom };

pub const ChainConfig = struct {
    id: Chain,
    genesis: types.GenesisSpec,
    spec: types.ChainSpec,

    const Self = @This();

    // for custom chains
    pub fn init(allocator: Allocator, chainId: Chain, chainOptsOrNull: ?[]const u8) !Self {
        switch (chainId) {
            .custom => {
                if (chainOptsOrNull) |*chainOpts| {
                    const options = json.ParseOptions{
                        .ignore_unknown_fields = true,
                        .allocate = .alloc_if_needed,
                    };

                    const genesis = (try json.parseFromSlice(types.GenesisSpec, allocator, chainOpts.*, options));
                    const spec = (try json.parseFromSlice(types.ChainSpec, allocator, chainOpts.*, options));

                    return Self{
                        .id = chainId,
                        .genesis = genesis.value,
                        .spec = spec.value,
                    };
                } else {
                    return ChainConfigError.InvalidChainSpec;
                }
            },
        }
    }
};

const ChainConfigError = error{
    InvalidChainSpec,
};

test "custom dev chain" {
    const dev_spec =
        \\{"preset": "mainnet", "name": "devchain1", "genesis_time": 1244}
    ;

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    const dev_config = try ChainConfig.init(arena_allocator.allocator(), Chain.custom, dev_spec);
    std.debug.print("dev config = {any}\n", .{dev_config});
}
