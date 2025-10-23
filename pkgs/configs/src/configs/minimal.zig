const types = @import("zeam-types");

pub const minimal = types.ChainSpec{
    .preset = types.Preset.minimal,
    .name = "minimal",
};
