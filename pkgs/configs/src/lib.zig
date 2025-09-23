const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const params = @import("@zeam/params");
const types = @import("@zeam/types");

const utils = @import("@zeam/utils");
pub const ChainOptions = utils.Partial(utils.MixIn(types.GenesisSpec, types.ChainSpec));

const configs = @import("./configs/mainnet.zig");
const Yaml = @import("yaml").Yaml;

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
                    // transfer ownership of any allocated memory in chainOpts to spec
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

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.spec.deinit(allocator);
    }
};

const ChainConfigError = error{
    InvalidChainSpec,
};

pub fn genesisConfigFromYAML(config: Yaml, override_genesis_time: ?u64) !types.GenesisSpec {
    const genesis_time: u64 = if (override_genesis_time) |gen_time| gen_time else @intCast(config.docs.items[0].map.get("GENESIS_TIME").?.int);
    const genesis_spec: types.GenesisSpec = .{
        .genesis_time = genesis_time,
        .num_validators = @intCast(config.docs.items[0].map.get("VALIDATOR_COUNT").?.int),
    };
    return genesis_spec;
}

test "load genesis config from yaml" {
    const yaml_content =
        \\# Genesis Settings
        \\GENESIS_TIME: 1704085200
        \\
        \\# Validator Settings  
        \\VALIDATOR_COUNT: 9
    ;

    var yaml: Yaml = .{ .source = yaml_content };
    defer yaml.deinit(std.testing.allocator);
    try yaml.load(std.testing.allocator);

    const genesis_config = try genesisConfigFromYAML(yaml, null);

    try std.testing.expect(genesis_config.genesis_time == 1704085200);
    try std.testing.expect(genesis_config.num_validators == 9);

    const genesis_config_override = try genesisConfigFromYAML(yaml, 1234);
    try std.testing.expect(genesis_config_override.genesis_time == 1234);
    try std.testing.expect(genesis_config_override.num_validators == 9);
}

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
    const dev_options = (try json.parseFromSlice(ChainOptions, arena_allocator.allocator(), dev_spec, options)).value;

    const dev_config = try ChainConfig.init(Chain.custom, dev_options);
    std.debug.print("dev config = {any}\n", .{dev_config});
    std.debug.print("chainoptions = {any}\n", .{ChainOptions{}});
}
