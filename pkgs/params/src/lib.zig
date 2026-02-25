// figure out a way to dynamically load these constants based on env
const std = @import("std");
const mainnetPreset = @import("./presets/mainnet.zig");
const types = @import("./types.zig");

pub const Preset = enum {
    mainnet,
    minimal,
};

const presets = .{ .mainnet = mainnetPreset.preset };
const xmss_configs = .{ .mainnet = mainnetPreset.xmss_config };

// figure out a way to set active preset
pub const activePreset = Preset.mainnet;
const activePresetValues = @field(presets, @tagName(activePreset));

pub const SECONDS_PER_SLOT = activePresetValues.SECONDS_PER_SLOT;

// SSZ capacity constants
pub const HISTORICAL_ROOTS_LIMIT = activePresetValues.HISTORICAL_ROOTS_LIMIT;
pub const VALIDATOR_REGISTRY_LIMIT = activePresetValues.VALIDATOR_REGISTRY_LIMIT;
pub const MAX_REQUEST_BLOCKS = activePresetValues.MAX_REQUEST_BLOCKS;

// XMSS signature scheme configuration
const XMSS_CONFIG = @field(xmss_configs, @tagName(activePreset));
pub const XMSS_HASH_LEN_FE = XMSS_CONFIG.HASH_LEN_FE;
pub const XMSS_RAND_LEN_FE = XMSS_CONFIG.RAND_LEN_FE;
pub const XMSS_NODE_LIST_LIMIT = XMSS_CONFIG.nodeListLimit();

// KoalaBear field element size
pub const FP_BYTES = types.FP_BYTES;

test "test preset loading" {
    try std.testing.expect(SECONDS_PER_SLOT == mainnetPreset.preset.SECONDS_PER_SLOT);
}

test "test xmss config" {
    try std.testing.expect(XMSS_NODE_LIST_LIMIT == (1 << 17)); // 2^(32/2 + 1) = 2^17 = 131072
}
