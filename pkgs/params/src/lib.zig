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

/// MAX_ATTESTATIONS_DATA — maximum number of distinct AttestationData entries a block may include.
/// devnet5 value is 8, set by leanSpec PR #717 (commit "limit max attestation data to 8"); see
/// leanSpec main `subspecs/chain/config.py` (`Uint8(8)`). NOTE: devnet4 used 16, and the vendored
/// `leanSpec/` submodule is pinned PRE-#717 so it still shows 16 — do not trust it for this value.
/// 8 also sits comfortably under leanMultisig MAX_RECURSIONS=16 (8 atts + 1 proposer = 9 ≤ 16).
/// Single source of truth — referenced by both the signature verifier (state-transition) and the
/// forkchoice import gate (node).
pub const MAX_ATTESTATIONS_DATA: usize = 8;

test "test preset loading" {
    try std.testing.expect(SECONDS_PER_SLOT == mainnetPreset.preset.SECONDS_PER_SLOT);
}
