const types = @import("zeam-types");

pub const mainnet = types.ChainSpec{
    // 10 minutes slot for proving purposes
    .preset = types.Preset.mainnet,
    .name = "mainnet",
};
