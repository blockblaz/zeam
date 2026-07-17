//! Compile-time selector for the optional ethp2p RS-broadcast adapter.
//!
//! Under `-Dethp2p=true` this resolves to the real `ethp2p_broadcast.zig`
//! (which imports `zig_ethp2p`); otherwise it resolves to the inert
//! `ethp2p_broadcast_stub.zig`, so the default build never touches the
//! `zig_ethp2p` dependency.

const build_options = @import("build_options");

/// Whether the ethp2p adapter was compiled in.
pub const enabled: bool = build_options.ethp2p;

const impl = if (enabled)
    @import("ethp2p_broadcast.zig")
else
    @import("ethp2p_broadcast_stub.zig");

pub const Ethp2pBroadcast = impl.Ethp2pBroadcast;
pub const Config = impl.Config;
