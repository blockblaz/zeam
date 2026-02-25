pub const PresetConfig = struct {
    SECONDS_PER_SLOT: u64,

    // SSZ List/Bitlist capacity constants
    HISTORICAL_ROOTS_LIMIT: u32,
    VALIDATOR_REGISTRY_LIMIT: u32,
    MAX_REQUEST_BLOCKS: u32,
};

/// XMSS signature scheme configuration.
/// Constants define the structure of the Generalized XMSS signature
/// matching leanSpec's configuration.
pub const XmssConfig = struct {
    /// The base-2 logarithm of the scheme's maximum lifetime.
    LOG_LIFETIME: u32,

    /// The length of the randomness rho in field elements.
    RAND_LEN_FE: u32,

    /// The output length of the hash function in field elements.
    HASH_LEN_FE: u32,

    /// Computed: Maximum nodes in signature lists (siblings, hashes).
    /// NODE_LIST_LIMIT = 2^(LOG_LIFETIME/2 + 1)
    pub fn nodeListLimit(self: XmssConfig) u32 {
        return @as(u32, 1) << @intCast(self.LOG_LIFETIME / 2 + 1);
    }
};

/// KoalaBear field element size in bytes.
pub const FP_BYTES: u32 = 4;
