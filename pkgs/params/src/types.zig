pub const PresetConfig = struct {
    SECONDS_PER_SLOT: u64,

    // SSZ List/Bitlist capacity constants
    HISTORICAL_ROOTS_LIMIT: u32,
    VALIDATOR_REGISTRY_LIMIT: u32,
    MAX_REQUEST_BLOCKS: u32,
};
