const interfaceFactory = @import("./interface.zig");
pub usingnamespace interfaceFactory;

const mockFactory = @import("./mock.zig");
pub usingnamespace mockFactory;

const ethlibp2pFactory = @import("./ethlibp2p.zig");
pub usingnamespace ethlibp2pFactory;

// Include tests
test "network tests" {
    _ = @import("./test.zig");
}
