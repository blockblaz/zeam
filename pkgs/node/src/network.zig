const std = @import("std");
const networks = @import("@zeam/network");

const NetworkBackend = union(enum) {
    mock: networks.Mock,
    ethlibp2p: networks.EthLibp2p,
};

var mock_network: networks.Mock = networks.Mock.init();

pub const Network = struct {
    comptime backend: networks.NetworkInterface = mock_network.getNetworkInterface(),

    const Self = @This();
    pub fn init(comptime backend: networks.NetworkInterface) Self {
        return Self{ .backend = backend };
    }
};

pub const default_network = Network.init(mock_network.getNetworkInterface());
