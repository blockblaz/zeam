pub const PresetConfig = struct {
    SECONDS_PER_SLOT: u64,

    // SSZ List/Bitlist capacity constants
    MAX_JUSTIFICATION_ROOTS: u32,
    MAX_JUSTIFICATION_VALIDATORS: u32,
    MAX_REQUEST_BLOCKS: u32,
};
