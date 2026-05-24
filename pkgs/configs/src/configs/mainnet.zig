const types = @import("zeam-types");

pub const mainnet = types.ChainSpec{
    // 10 minutes slot for proving purposes
    .preset = types.Preset.mainnet,
    .name = "mainnet",
    .fork_digest = "00000000",
    .attestation_committee_count = 1,
    // devnet5: 8 attestations + 1 proposer component = 9, within the Type-2 merge recursion limit of 16.
    .max_attestations_data = 8,
};
