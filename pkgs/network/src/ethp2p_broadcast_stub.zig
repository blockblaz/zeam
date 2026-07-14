//! No-op stand-in for `ethp2p_broadcast.zig`, selected by `ethp2p.zig` when
//! the build was not configured with `-Dethp2p=true`. It never imports
//! `zig_ethp2p`, so the default build neither fetches nor compiles that
//! dependency. The public API mirrors the real adapter so call sites compile
//! unchanged; every method is an inert stub.

const std = @import("std");
const interface = @import("interface.zig");
const config_mod = @import("ethp2p_config.zig");

pub const Config = config_mod.Config;

pub const Ethp2pBroadcast = struct {
    pub fn start(
        allocator: std.mem.Allocator,
        backend: interface.NetworkInterface,
        cfg: Config,
    ) !*Ethp2pBroadcast {
        _ = allocator;
        _ = backend;
        _ = cfg;
        // The adapter is compiled out; enabling it at runtime without
        // `-Dethp2p=true` is a configuration error.
        return error.Ethp2pNotCompiledIn;
    }

    pub fn deinit(self: *Ethp2pBroadcast) void {
        _ = self;
    }

    pub fn publishGossip(self: *Ethp2pBroadcast, msg: *const interface.GossipMessage) void {
        _ = self;
        _ = msg;
    }

    pub fn tick(self: *Ethp2pBroadcast, now_ms: i64) void {
        _ = self;
        _ = now_ms;
    }
};
