const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const params = @import("@zeam/params");
const types = @import("@zeam/types");

const utils = @import("@zeam/utils");
pub const ChainOptions = utils.Partial(utils.MixIn(types.GenesisSpec, types.ChainSpec));

const configs = @import("./configs/mainnet.zig");

pub const Chain = enum { custom };

pub const ChainConfig = struct {
    id: Chain,
    genesis: types.GenesisSpec,
    spec: types.ChainSpec,

    const Self = @This();

    // for custom chains
    pub fn init(chainId: Chain, chainOptsOrNull: ?ChainOptions) !Self {
        switch (chainId) {
            .custom => {
                if (chainOptsOrNull) |*chainOpts| {
                    const genesis = utils.Cast(types.GenesisSpec, chainOpts);
                    const spec = utils.Cast(types.ChainSpec, chainOpts);

                    return Self{
                        .id = chainId,
                        .genesis = genesis,
                        .spec = spec,
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
        \\{"preset": "mainnet", "name": "devchain1", "genesis_time": 1244, "num_validators": 4}
    ;

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const dev_options = (try json.parseFromSlice(ChainOptions, arena_allocator.allocator(), dev_spec, options));

    const dev_config = try ChainConfig.init(Chain.custom, dev_options);
    std.debug.print("dev config = {any}\n", .{dev_config});
    std.debug.print("chainoptions = {any}\n", .{ChainOptions{}});
}
