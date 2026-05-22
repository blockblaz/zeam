const types = @import("zeam-types");

pub const mainnet = types.ChainSpec{
    // 10 minutes slot for proving purposes
    .preset = types.Preset.mainnet,
    .name = "mainnet",
    .fork_digest = "00000000",
    .attestation_committee_count = 1,
    // devnet5: MAX_ATTESTATIONS_DATA = 8 (leanSpec #717); leaves room for the proposer component
    // within leanMultisig's MAX_RECURSIONS=16 Type-2 merge limit (8 + 1 = 9 ≤ 16).
    .max_attestations_data = 8,
};
