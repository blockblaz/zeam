// figure out a way to dynamically load these constants based on env
const std = @import("std");
const mainnetPreset = @import("./presets/mainnet.zig");
pub const Preset = enum {
    mainnet,
    minimal,
};

const presets = .{ .mainnet = mainnetPreset.preset };
// figure out a way to set active preset
pub const activePreset = Preset.mainnet;
const activePresetValues = @field(presets, @tagName(activePreset));

pub const SECONDS_PER_SLOT = activePresetValues.SECONDS_PER_SLOT;

// SSZ capacity constants
pub const HISTORICAL_ROOTS_LIMIT = activePresetValues.HISTORICAL_ROOTS_LIMIT;
pub const VALIDATOR_REGISTRY_LIMIT = activePresetValues.VALIDATOR_REGISTRY_LIMIT;
pub const MAX_REQUEST_BLOCKS = activePresetValues.MAX_REQUEST_BLOCKS;

/// Max distinct AttestationData entries per block. devnet5 value is 8 (leanSpec #717); was 16 in
/// devnet4. Single source of truth, referenced by the signature verifier and the forkchoice gate.
pub const MAX_ATTESTATIONS_DATA: usize = 8;

test "test preset loading" {
    try std.testing.expect(SECONDS_PER_SLOT == mainnetPreset.preset.SECONDS_PER_SLOT);
}
