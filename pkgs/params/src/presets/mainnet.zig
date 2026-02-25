const types = @import("../types.zig");

pub const preset = types.PresetConfig{
    .SECONDS_PER_SLOT = 4,

    // SSZ capacity constants based on leanSpecs
    .HISTORICAL_ROOTS_LIMIT = 1 << 18, // 2^18 = 262144
    .VALIDATOR_REGISTRY_LIMIT = 1 << 12, // 2^12 = 4096
    .MAX_REQUEST_BLOCKS = 1024,
};

/// XMSS configuration matching leanSpec.
pub const xmss_config = types.XmssConfig{
    .LOG_LIFETIME = 32,
    .RAND_LEN_FE = 7,
    .HASH_LEN_FE = 8,
};
