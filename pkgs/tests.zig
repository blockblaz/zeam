comptime {
    _ = @import("state-transition/src/lib.zig");
    // uncomment in #3
    // _ = @import("state-proving-manager/src/manager.zig");
    // uncomment after rebase / fixing preset issue
    // _ = @import("params/src/lib.zig");
    _ = @import("cli/src/main.zig");
    // uncomment after rebase / fixing preset issue
    // _ = @import("types/src/lib.zig");
    _ = @import("./beam-node/src/node.zig");
}
