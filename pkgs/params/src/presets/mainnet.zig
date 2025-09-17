const types = @import("../types.zig");

pub const preset = types.PresetConfig{
    .SECONDS_PER_SLOT = 4,

    // SSZ capacity constants based on zeam consensus requirements
    .MAX_JUSTIFICATION_ROOTS = 256,        // Historical justification tracking
    .MAX_JUSTIFICATION_VALIDATORS = 4096,  // Matches MAX_VALIDATORS in types
    .MAX_REQUEST_BLOCKS = 1024,           // P2P block request capacity
};
