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

/// Intermediate structure for genesis config before keys are generated
pub const GenesisConfig = struct {
    genesis_time: u64,
    validator_count: usize,
};

/// Parse genesis configuration from YAML (without generating keys)
/// Returns genesis time and validator count. The caller is responsible for
/// generating validator keys and creating the full GenesisSpec.
pub fn genesisConfigFromYAML(config: Yaml, override_genesis_time: ?u64) !GenesisConfig {
    // Parse GENESIS_TIME from YAML
    const genesis_time_value = config.docs.items[0].map.get("GENESIS_TIME") orelse return error.MissingGenesisTime;
    if (genesis_time_value != .int) return error.InvalidGenesisTime;
    const genesis_time = if (override_genesis_time) |override| override else @as(u64, @intCast(genesis_time_value.int));

    // Parse VALIDATOR_COUNT from YAML
    const validator_count_value = config.docs.items[0].map.get("VALIDATOR_COUNT") orelse return error.MissingValidatorCount;
    if (validator_count_value != .int) return error.InvalidValidatorCount;
    const validator_count: usize = @intCast(validator_count_value.int);

    if (validator_count == 0) return error.InvalidValidatorCount;

    return GenesisConfig{
        .genesis_time = genesis_time,
        .validator_count = validator_count,
    };
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
    try std.testing.expectEqual(@as(u64, 1704085200), genesis_config.genesis_time);
    try std.testing.expectEqual(@as(usize, 9), genesis_config.validator_count);

    const genesis_config_override = try genesisConfigFromYAML(yaml, 1234);
    try std.testing.expectEqual(@as(u64, 1234), genesis_config_override.genesis_time);
    try std.testing.expectEqual(@as(usize, 9), genesis_config_override.validator_count);
}

// TODO: Enable and update this test once the keymanager file-reading PR is added (followup PR)
// JSON parsing for genesis config needs to support validator_pubkeys instead of num_validators
// test "custom dev chain" {
//     const dev_spec =
//         \\{"preset": "mainnet", "name": "devchain1", "genesis_time": 1244, "num_validators": 4}
//     ;
//
//     var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
//     defer arena_allocator.deinit();
//
//     const options = json.ParseOptions{
//         .ignore_unknown_fields = true,
//         .allocate = .alloc_if_needed,
//     };
//     const dev_options = (try json.parseFromSlice(ChainOptions, arena_allocator.allocator(), dev_spec, options)).value;
//
//     const dev_config = try ChainConfig.init(Chain.custom, dev_options);
//     std.debug.print("dev config = {any}\n", .{dev_config});
//     std.debug.print("chainoptions = {any}\n", .{ChainOptions{}});
// }
