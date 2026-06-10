const types = @import("zeam-types");

pub const mainnet = types.ChainSpec{
    // 10 minutes slot for proving purposes
    .preset = types.Preset.mainnet,
    .name = "mainnet",
    .fork_digest = "00000000",
    .attestation_committee_count = 1,
    // MAX_ATTESTATIONS_DATA = 8 (== params.MAX_ATTESTATIONS_DATA, the
    // verifySignatures hard cap). Must not exceed it or the builder would
    // assemble blocks the verify path rejects.
    .max_attestations_data = 8,
};
