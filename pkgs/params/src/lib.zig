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

test "test preset loading" {
    try std.testing.expect(SECONDS_PER_SLOT == 4);
}
