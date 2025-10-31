const types = @import("../types.zig");

pub const preset = types.PresetConfig{
    .SECONDS_PER_SLOT = 4,

    // SSZ capacity constants - minimal values for testing
    .HISTORICAL_ROOTS_LIMIT = 1 << 10, // 2^10 = 1024
    .VALIDATOR_REGISTRY_LIMIT = 1 << 8, // 2^8 = 256
    .MAX_REQUEST_BLOCKS = 64,
};
