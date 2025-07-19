const std = @import("std");
const networks = @import("@zeam/network");

const NetworkBackend = union(enum) {
    mock: networks.Mock,
    ethlibp2p: networks.EthLibp2p,
};

pub const Network = struct {
    backend: networks.NetworkInterface,

    const Self = @This();
    pub fn init(backend: networks.NetworkInterface) Self {
        return Self{ .backend = backend };
    }
};
