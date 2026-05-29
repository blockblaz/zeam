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

// Preset default, optionally overridden at build time by `-Dseconds-per-slot` (test/sim only — lets
// the simtest widen the slot so the real prover fits; prod omits the flag and uses the preset).
// `build_options.seconds_per_slot_override` is comptime-known, so dependent timing math stays comptime.
pub const SECONDS_PER_SLOT = build_options.seconds_per_slot_override orelse activePresetValues.SECONDS_PER_SLOT;

// SSZ capacity constants
pub const HISTORICAL_ROOTS_LIMIT = activePresetValues.HISTORICAL_ROOTS_LIMIT;
pub const VALIDATOR_REGISTRY_LIMIT = activePresetValues.VALIDATOR_REGISTRY_LIMIT;
pub const MAX_REQUEST_BLOCKS = activePresetValues.MAX_REQUEST_BLOCKS;

// devnet5 / leanSpec #717: max distinct AttestationData entries a block body may carry. Bounds the
// number of Type-1 components merged into the single Type-2 block proof, capping both proposer
// merge cost and importer verify cost.
pub const MAX_ATTESTATIONS_DATA: usize = 8;

// devnet5: soft wall-clock budget for one aggregation pass. The per-att_data Type-1 aggregation is
// a recursive-STARK prove whose cost grows with the number of distinct AttestationData groups; left
// unbounded it can run past the slot and starve justification. Matching ethlambda, an aggregation
// worker stops scheduling new groups once this budget is spent and emits the aggregations it has
// already committed (a partial pass), keeping aggregates timely enough to finalize.
pub const AGGREGATION_DEADLINE_MS: u64 = 750;

test "test preset loading" {
    // Only assert the preset value when no -Dseconds-per-slot override is in effect (the override
    // is test/sim-only and intentionally diverges from the preset).
    if (build_options.seconds_per_slot_override == null) {
        try std.testing.expect(SECONDS_PER_SLOT == mainnetPreset.preset.SECONDS_PER_SLOT);
    }
}
