//! Shared config for the optional ethp2p RS-broadcast adapter. Kept in its own
//! file so the real adapter and its stub share one type without either
//! importing the other.

/// Startup parameters for `Ethp2pBroadcast`. All peer/listen fields are
/// optional: with none set the adapter runs dial-only with no peers, which is
/// enough to tee gossip publishes into origin RS sessions (self-interop and
/// cross-process delivery need `listen_addr` + `server_*_pem_path` on both
/// ends and `static_peers` pointing at each other).
pub const Config = struct {
    /// Peer id announced in the BCAST handshake / used as the RS engine id.
    local_peer_id: []const u8,
    /// "host:port" to bind the QUIC listen (server) endpoint. Null → dial-only.
    listen_addr: ?[]const u8 = null,
    /// TLS server identity (PEM paths). Required when `listen_addr` is set.
    server_certificate_pem_path: ?[]const u8 = null,
    server_private_key_pem_path: ?[]const u8 = null,
    /// Remote "host:port" peers to dial at startup (best-effort).
    static_peers: []const []const u8 = &.{},
    /// TLS server name (SNI) used on dials.
    server_name: []const u8 = "127.0.0.1",
    /// Per-channel delivery ring capacity.
    sub_capacity: usize = 64,
};
