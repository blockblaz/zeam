const types = @import("../types.zig");

pub const preset = types.PresetConfig{
    .SECONDS_PER_SLOT = 4,

    // SSZ capacity constants based on zeam consensus requirements
    // Using very small values for devnet0 to avoid SSZ capacity overflow
    .HISTORICAL_ROOTS_LIMIT = 4, // Historical justification tracking (reduced from 256)
    .VALIDATOR_REGISTRY_LIMIT = 8, // MAX_VALIDATORS (reduced from 4096)
    .MAX_REQUEST_BLOCKS = 1024, // P2P block request capacity
};
