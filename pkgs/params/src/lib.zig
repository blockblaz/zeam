// Compile-time preset configuration
const std = @import("std");
const build_options = @import("build_options");
const mainnetPreset = @import("./presets/mainnet.zig");
const minimalPreset = @import("./presets/minimal.zig");
const types = @import("./types.zig");
const PresetConfig = types.PresetConfig;

pub const Preset = enum {
    mainnet,
    minimal,
};

const presets = .{
    .mainnet = mainnetPreset.preset,
    .minimal = minimalPreset.preset,
};

// Get preset from build options at compile time
const preset_name = build_options.preset;
pub const activePreset = std.meta.stringToEnum(Preset, preset_name) orelse @panic("Invalid preset specified in build options");
const activePresetValues = @field(presets, @tagName(activePreset));

pub const SECONDS_PER_SLOT = activePresetValues.SECONDS_PER_SLOT;

// SSZ capacity constants
pub const HISTORICAL_ROOTS_LIMIT = activePresetValues.HISTORICAL_ROOTS_LIMIT;
pub const VALIDATOR_REGISTRY_LIMIT = activePresetValues.VALIDATOR_REGISTRY_LIMIT;
pub const MAX_REQUEST_BLOCKS = activePresetValues.MAX_REQUEST_BLOCKS;

// Function to get preset values dynamically
pub fn getPresetValues(preset_type: Preset) PresetConfig {
    return switch (preset_type) {
        .mainnet => presets.mainnet,
        .minimal => presets.minimal,
    };
}

test "test preset loading" {
    try std.testing.expect(SECONDS_PER_SLOT == mainnetPreset.preset.SECONDS_PER_SLOT);
}

test "test preset values" {
    const mainnet_values = getPresetValues(.mainnet);
    const minimal_values = getPresetValues(.minimal);

    // Test that different presets have different values
    try std.testing.expect(mainnet_values.SECONDS_PER_SLOT == 4);
    try std.testing.expect(minimal_values.SECONDS_PER_SLOT == 4);

    // Test that minimal has smaller limits
    try std.testing.expect(minimal_values.HISTORICAL_ROOTS_LIMIT < mainnet_values.HISTORICAL_ROOTS_LIMIT);
    try std.testing.expect(minimal_values.VALIDATOR_REGISTRY_LIMIT < mainnet_values.VALIDATOR_REGISTRY_LIMIT);
    try std.testing.expect(minimal_values.MAX_REQUEST_BLOCKS < mainnet_values.MAX_REQUEST_BLOCKS);
}

test "test compile-time preset configuration" {
    // Test that activePreset matches the build option
    const expected_preset = std.meta.stringToEnum(Preset, build_options.preset) orelse @panic("Invalid preset in build options");
    try std.testing.expect(activePreset == expected_preset);

    // Test that constants match the active preset
    const expected_values = getPresetValues(activePreset);
    try std.testing.expect(SECONDS_PER_SLOT == expected_values.SECONDS_PER_SLOT);
    try std.testing.expect(HISTORICAL_ROOTS_LIMIT == expected_values.HISTORICAL_ROOTS_LIMIT);
    try std.testing.expect(VALIDATOR_REGISTRY_LIMIT == expected_values.VALIDATOR_REGISTRY_LIMIT);
    try std.testing.expect(MAX_REQUEST_BLOCKS == expected_values.MAX_REQUEST_BLOCKS);
}

test "test preset-specific values" {
    // Test mainnet preset values
    if (activePreset == .mainnet) {
        try std.testing.expect(HISTORICAL_ROOTS_LIMIT == 262144);
        try std.testing.expect(VALIDATOR_REGISTRY_LIMIT == 4096);
        try std.testing.expect(MAX_REQUEST_BLOCKS == 1024);
    }

    // Test minimal preset values
    if (activePreset == .minimal) {
        try std.testing.expect(HISTORICAL_ROOTS_LIMIT == 1024);
        try std.testing.expect(VALIDATOR_REGISTRY_LIMIT == 256);
        try std.testing.expect(MAX_REQUEST_BLOCKS == 64);
    }
}
