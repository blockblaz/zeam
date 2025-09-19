const types = @import("../types.zig");

pub const preset = types.PresetConfig{
    .SECONDS_PER_SLOT = 4,

    // SSZ capacity constants based on leanSpecs
    // reduced size of roots limit because of following build issue
    // caused by super big stack allocated bounded lists
    // error: warning: mock.zig:27:0: stack frame size (5002379528) exceeds limit (4294967295) in function 'mock.genMockChain'
    // even beam run command results into core dumped
    .HISTORICAL_ROOTS_LIMIT = 1 << 10, // 2^18 = 262144
    .VALIDATOR_REGISTRY_LIMIT = 1 << 4, // 2^12 = 4096
    .MAX_REQUEST_BLOCKS = 1024,
};
