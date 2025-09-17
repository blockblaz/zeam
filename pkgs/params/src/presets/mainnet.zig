const types = @import("../types.zig");

pub const preset = types.PresetConfig{
    .SECONDS_PER_SLOT = 4,

    // SSZ capacity constants based on zeam consensus requirements
    .HISTORICAL_ROOTS_LIMIT = 256,        // Historical justification tracking
    .VALIDATOR_REGISTRY_LIMIT = 4096,     // MAX_VALIDATORS
    .MAX_REQUEST_BLOCKS = 1024,           // P2P block request capacity
};
