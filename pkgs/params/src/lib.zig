// figure out a way to dynamically load these constants based on env
const std = @import("std");
const mainnetPreset = @import("./presets/mainnet.zig");
const build_options = @import("build_options");
pub const Preset = enum {
    mainnet,
    minimal,
};

const presets = .{ .mainnet = mainnetPreset.preset };
// figure out a way to set active preset
pub const activePreset = Preset.mainnet;
const activePresetValues = @field(presets, @tagName(activePreset));

// Preset value unless overridden at build time. Tests/sims may widen the slot.
pub const SECONDS_PER_SLOT = build_options.seconds_per_slot_override orelse activePresetValues.SECONDS_PER_SLOT;

// SSZ capacity constants
pub const HISTORICAL_ROOTS_LIMIT = activePresetValues.HISTORICAL_ROOTS_LIMIT;
pub const VALIDATOR_REGISTRY_LIMIT = activePresetValues.VALIDATOR_REGISTRY_LIMIT;
pub const MAX_REQUEST_BLOCKS = activePresetValues.MAX_REQUEST_BLOCKS;

// Max distinct AttestationData entries a block body may carry. Bounds the number of Type-1
// components merged into the single Type-2 block proof, capping both proposer merge cost and
// importer verify cost.
pub const MAX_ATTESTATIONS_DATA: usize = 8;

// Soft wall-clock budget for one aggregation pass. The per-att_data Type-1 aggregation is
// a recursive-STARK prove whose cost grows with the number of distinct AttestationData groups; left
// unbounded it can run past the slot and starve justification. Matching ethlambda, an aggregation
// worker stops scheduling new groups once this budget is spent and emits the aggregations it has
// already committed (a partial pass), keeping aggregates timely enough to finalize.
pub const AGGREGATION_DEADLINE_MS: u64 = 750;

test "test preset loading" {
    // The override intentionally diverges from the preset, so only check this without it.
    if (build_options.seconds_per_slot_override == null) {
        try std.testing.expect(SECONDS_PER_SLOT == mainnetPreset.preset.SECONDS_PER_SLOT);
    }
}
