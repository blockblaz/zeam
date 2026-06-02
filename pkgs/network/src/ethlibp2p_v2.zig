//! v2 EthLibp2p — pure-Zig replacement for the Rust libp2p-glue path, built
//! on top of `zig_libp2p` v0.1.0.
//!
//! ## Status: SKELETON (post-PR work)
//!
//! This file is the first slice of replacing `ethlibp2p.zig`'s Rust-FFI
//! consumer with a native Zig stack. It wires:
//!
//!   - `zig_libp2p.host.Host` bundle (Swarm + Gossipsub + ReqResp + ConnMgr).
//!   - The handlers zeam's network-package consumers register today (gossip,
//!     req/resp, peer events) via the same `interface.zig` types.
//!   - A driver thread that drains `host.nextEvent` and dispatches each event
//!     to the registered handlers.
//!
//! What it does NOT do yet (tracked as follow-up commits on
//! `feat/replace-libp2p-glue`):
//!
//!   - TCP / QUIC listener bring-up. The Rust glue today owns the libp2p
//!     swarm's listener + dialer; zig-libp2p makes that the embedder's
//!     responsibility. The next commit on this branch wires a
//!     `zl.transport.quic_endpoint.QuicListener` per `listen_address` and
//!     plumbs accepted streams through multistream-select into the Host
//!     hooks (`onConnectionEstablished`, `handleGossipRpc`,
//!     `registerInboundReqRespChannel`).
//!   - Snappy framing + SSZ deserialisation of gossip payloads. zeam's
//!     existing GenericGossipHandler does this for the FFI path; v2 reuses
//!     the same handler by feeding it `interface.GossipMessage`. That
//!     translation lives in `dispatchGossipMessage` below — currently a TODO.
//!   - Bootnode / connect_peers dial scheduling. ConnectionManager has the
//!     primitives (`registerKnownPeer`, `tick`); the v2 wiring just needs
//!     to call them at init time and on a heartbeat tick.
//!   - Multi-network slot accounting. The Rust glue stores per-network state
//!     in a global `[3]NetworkSlot` array; in Zig each network is its own
//!     `EthLibp2pV2` instance, owned by the embedder.
//!   - Hot-swap / parity with the Rust path. v2 lives alongside the legacy
//!     path; lib.zig exposes a build-flag-gated factory so consumers can
//!     opt in one network at a time.
//!
//! See `pkgs/network/README.md` (added on this branch) for the full
//! migration plan.

const std = @import("std");
const Allocator = std.mem.Allocator;
const interface = @import("interface.zig");
const zeam_utils = @import("@zeam/utils");
const xev = @import("xev");

const zl = @import("zig_libp2p");

/// Configuration mirroring `EthLibp2pParams` (`ethlibp2p.zig`) for the subset
/// the v2 path consumes today. Anything not listed here (`fork_digest`,
/// `local_private_key`, etc.) lives on the legacy struct and will migrate
/// once the corresponding wiring lands.
pub const EthLibp2pV2Params = struct {
    network_id: u32,
    /// Multiaddr strings, comma-or-newline-separated by the caller. Today
    /// only QUIC listeners are wired (`/ip4/.../udp/.../quic-v1`); TCP comes
    /// when zquic upstream exposes `tls.nonblock`.
    listen_addresses: []const u8,
    /// Known-peer multiaddrs to dial at startup.
    connect_peers: []const u8,
    // Per-network state lives on the embedder; v2 doesn't yet need
    // the node registry pointer the legacy params carry. Will surface
    // once `dispatchPeerConnected` learns to look up the registry to
    // resolve human-readable names for the logger.
};

/// Per-instance state. One per network slot.
pub const EthLibp2pV2 = struct {
    allocator: Allocator,
    host: *zl.host.Host,
    /// Background thread that drains `host.nextEvent` and dispatches into
    /// the registered handlers.
    runner: ?std.Thread = null,
    shutdown_flag: std.atomic.Value(bool) = .init(false),

    /// Handlers — same shapes as the legacy path so consumers don't change.
    gossip_handler: ?*interface.GenericGossipHandler = null,
    peer_event_handler: ?*interface.PeerEventHandler = null,
    reqresp_handler: ?*interface.ReqRespRequestHandler = null,

    pub fn init(
        allocator: Allocator,
        loop: *xev.Loop,
        params: EthLibp2pV2Params,
        logger: zeam_utils.ModuleLogger,
    ) !*EthLibp2pV2 {
        _ = loop;
        _ = logger;
        _ = params;

        const me = try zl.identity.PeerId.random();
        const host = try zl.host.Host.create(.{
            .allocator = allocator,
            .local_peer = me,
            .gossipsub = .{ .local_peer_id = me },
        });
        errdefer host.destroy();

        try host.startBackground();
        if (!host.waitUntilReady(5_000)) return error.HostNotReady;

        const self = try allocator.create(EthLibp2pV2);
        self.* = .{ .allocator = allocator, .host = host };
        return self;
    }

    pub fn deinit(self: *EthLibp2pV2) void {
        self.shutdown_flag.store(true, .release);
        self.host.shutdown();
        if (self.runner) |t| t.join();
        self.host.destroy();
        self.allocator.destroy(self);
    }

    // ── Public API mirroring the legacy callback-registration entry points.

    pub fn publish(self: *EthLibp2pV2, data: *const interface.GossipMessage) anyerror!bool {
        // TODO(v2): encode `data.payload` per the topic's snappy/SSZ rules,
        // then `host.publish(topic_bytes, encoded)`. The legacy path's
        // `gossipMessageToFrame` helper has the per-topic dispatch; lift it.
        _ = data;
        _ = self;
        return error.NotYetImplemented;
    }

    pub fn subscribe(self: *EthLibp2pV2, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        // TODO(v2): for each `topic` render its wire form via the existing
        // `LeanNetworkTopic.encode` helper, then `host.subscribe(wire)`.
        // Stash the handler so `dispatchGossipMessage` can invoke it.
        _ = topics;
        _ = handler;
        _ = self;
        return error.NotYetImplemented;
    }

    pub fn subscribeReqResp(self: *EthLibp2pV2, handler: interface.OnReqRespRequestCbHandler) anyerror!void {
        _ = handler;
        _ = self;
        return error.NotYetImplemented;
    }

    pub fn subscribePeerEvents(self: *EthLibp2pV2, handler: interface.OnPeerEventCbHandler) anyerror!void {
        _ = handler;
        _ = self;
        return error.NotYetImplemented;
    }

    // ── Event-drain loop (background thread).

    fn drainEvents(self: *EthLibp2pV2) void {
        while (!self.shutdown_flag.load(.acquire)) {
            var ev = self.host.nextEvent(50) catch |e| switch (e) {
                error.Timeout => continue,
                error.QueueClosed => return,
            };
            defer ev.deinit(self.allocator);

            switch (ev) {
                .gossip_message => |m| self.dispatchGossipMessage(m),
                .rpc_request => |r| self.dispatchRpcRequest(r),
                .rpc_response_chunk => |r| self.dispatchRpcResponseChunk(r),
                .rpc_response_end => |r| self.dispatchRpcResponseEnd(r),
                .rpc_error_response => |r| self.dispatchRpcError(r),
                .peer_connected => |p| self.dispatchPeerConnected(p),
                .peer_disconnected => |p| self.dispatchPeerDisconnected(p),
                .peer_connection_failed => |p| self.dispatchPeerConnectionFailed(p),
                .log => {},
                .connection_trim_recommended => {},
                .swarm_closed => return,
            }
        }
    }

    fn dispatchGossipMessage(self: *EthLibp2pV2, m: anytype) void {
        // TODO(v2): decode topic + snappy + SSZ into `interface.GossipMessage`,
        // then invoke `self.gossip_handler.?.onGossip(...)`.
        _ = m;
        _ = self;
    }

    fn dispatchRpcRequest(self: *EthLibp2pV2, r: anytype) void {
        _ = r;
        _ = self;
    }
    fn dispatchRpcResponseChunk(self: *EthLibp2pV2, r: anytype) void {
        _ = r;
        _ = self;
    }
    fn dispatchRpcResponseEnd(self: *EthLibp2pV2, r: anytype) void {
        _ = r;
        _ = self;
    }
    fn dispatchRpcError(self: *EthLibp2pV2, r: anytype) void {
        _ = r;
        _ = self;
    }
    fn dispatchPeerConnected(self: *EthLibp2pV2, p: anytype) void {
        _ = p;
        _ = self;
    }
    fn dispatchPeerDisconnected(self: *EthLibp2pV2, p: anytype) void {
        _ = p;
        _ = self;
    }
    fn dispatchPeerConnectionFailed(self: *EthLibp2pV2, p: anytype) void {
        _ = p;
        _ = self;
    }
};

test "EthLibp2pV2 compiles against zig-libp2p v0.1.0" {
    // Smoke test: zig_libp2p's public surface resolves and our skeleton
    // compiles. End-to-end tests come once the dispatcher fills in.
    const T = @TypeOf(EthLibp2pV2);
    _ = T;
}
