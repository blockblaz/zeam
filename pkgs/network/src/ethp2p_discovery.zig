//! EthP2PDiscovery — discv5-based peer discovery backed by zig-ethp2p.
//!
//! Replaces the Rust libp2p-glue layer for peer discovery.
//! Provides the same `PeerEvents` vtable consumed by the rest of zeam so that
//! `EthP2PNetwork` (gossip + req/resp) is unaffected by the change.
//!
//! Architecture:
//!   • `discv5_node.Node` handles the discv5 UDP wire protocol (PING / FINDNODE /
//!     WHOAREYOU / HANDSHAKE) using its own non-blocking socket.
//!   • `PeerManager` bridges discv5 routing table → warmup scheduler → QUIC dial.
//!   • A dedicated poll thread drives both at ~100 ms cadence.
//!   • When `PeerManager.dialPeer` succeeds it fires `on_peer_dialed`; we convert
//!     the 32-byte NodeId to a 64-char hex string and dispatch `onPeerConnected`
//!     to all registered `OnPeerEventCbHandler` subscribers.
//!
//! Bootstrap: callers supply pre-parsed `DiscoveryBootstrapEntry` values
//! (NodeId + UDP address), derived from ENR text in the CLI layer.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const zig_ethp2p = @import("zig_ethp2p");
const discv5_node_mod = zig_ethp2p.discovery.discv5_node;
const discv5_crypto = zig_ethp2p.discovery.discv5_crypto;
const discv5_table = zig_ethp2p.discovery.discv5_table;
const peering_table_mod = zig_ethp2p.discovery.peering_table;
const peering_pool_mod = zig_ethp2p.discovery.peering_pool;
const peering_warmup_mod = zig_ethp2p.discovery.peering_warmup;
const peer_manager_mod = zig_ethp2p.discovery.peer_manager;

const zeam_utils = @import("@zeam/utils");
const interface = @import("./interface.zig");
const node_registry = @import("./node_registry.zig");
const NodeNameRegistry = node_registry.NodeNameRegistry;

/// Poll interval for the background drive thread.
const POLL_INTERVAL_NS: u64 = 100 * std.time.ns_per_ms;

/// A pre-parsed bootstrap peer entry.
/// Callers (e.g. the CLI) derive these from ENR text strings.
pub const DiscoveryBootstrapEntry = struct {
    node_id: [32]u8,
    udp_addr: std.net.Address,
};

/// Compute a discv5 NodeId (keccak256 of uncompressed pubkey[1..]) from a
/// 33-byte compressed secp256k1 public key.  Exposed so that callers can
/// derive bootstrap NodeIds from ENR secp256k1 fields without importing
/// zig-ethp2p directly.
pub fn nodeIdFromCompressedPubkey(pubkey: [33]u8) !discv5_table.NodeId {
    return discv5_crypto.nodeIdFromPubkey(pubkey);
}

pub const EthP2PDiscoveryParams = struct {
    networkId: u32,
    /// Raw 32-byte secp256k1 private key for the local node.
    local_privkey: [32]u8,
    /// UDP port for the discv5 listener (0 = OS-assigned).
    listen_port: u16,
    /// Bootstrap peers; may be empty for a sole bootstrap node.
    bootstrap_entries: []const DiscoveryBootstrapEntry,
    node_registry: *const NodeNameRegistry,
};

pub const EthP2PDiscovery = struct {
    allocator: Allocator,
    params: EthP2PDiscoveryParams,

    discv5: discv5_node_mod.Node,
    peers: peering_table_mod.PeerTable,
    pool: peering_pool_mod.Pool,
    warmup: peering_warmup_mod.Scheduler,
    manager: peer_manager_mod.PeerManager,

    peer_event_handler: interface.PeerEventHandler,

    poll_thread: ?Thread = null,
    poll_running: std.atomic.Value(bool),

    logger: zeam_utils.ModuleLogger,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        params: EthP2PDiscoveryParams,
        logger: zeam_utils.ModuleLogger,
    ) !Self {
        var peer_event_handler = try interface.PeerEventHandler.init(
            allocator,
            params.networkId,
            logger,
            params.node_registry,
        );
        errdefer peer_event_handler.deinit();

        const listen_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, params.listen_port);
        var discv5 = try discv5_node_mod.Node.init(allocator, .{
            .listen_addr = listen_addr,
            .local_privkey = params.local_privkey,
        });
        errdefer discv5.deinit();

        var peers = peering_table_mod.PeerTable.init(allocator);
        errdefer peers.deinit();

        var pool = peering_pool_mod.Pool.init(allocator);
        errdefer pool.deinit();

        var warmup = peering_warmup_mod.Scheduler.init(allocator);
        errdefer warmup.deinit();

        const manager = peer_manager_mod.PeerManager.init(allocator, .{}, &discv5, &peers, &warmup, &pool);

        // Add pre-parsed bootstrap entries to the discv5 routing table.
        for (params.bootstrap_entries) |entry| {
            discv5.addBootstrap(.{
                .node_id = entry.node_id,
                .udp_addr = entry.udp_addr,
                .enr_seq = 0,
                .last_seen_ns = 0,
            });
        }

        var self = Self{
            .allocator = allocator,
            .params = params,
            .discv5 = discv5,
            .peers = peers,
            .pool = pool,
            .warmup = warmup,
            .manager = manager,
            .peer_event_handler = peer_event_handler,
            .poll_running = std.atomic.Value(bool).init(false),
            .logger = logger,
        };

        // Wire the on_peer_dialed callback so we can forward to subscribers.
        self.manager.on_peer_dialed = onPeerDialedCb;
        self.manager.on_peer_dialed_ctx = &self;

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.discv5.deinit();
        self.peers.deinit();
        self.pool.deinit();
        self.warmup.deinit();
        self.peer_event_handler.deinit();
    }

    /// Bind the discv5 UDP socket and start the background poll thread.
    pub fn start(self: *Self) !void {
        try self.discv5.start();
        self.logger.info(
            "network-{d}:: discv5 listener started on port {d}",
            .{ self.params.networkId, self.params.listen_port },
        );

        self.poll_running.store(true, .release);
        self.poll_thread = try Thread.spawn(.{}, pollLoop, .{self});
    }

    fn stop(self: *Self) void {
        self.poll_running.store(false, .release);
        if (self.poll_thread) |t| {
            t.join();
            self.poll_thread = null;
        }
        self.discv5.stop();
    }

    /// Background thread: drives discv5 UDP I/O and peer warmup every ~100 ms.
    fn pollLoop(self: *Self) void {
        while (self.poll_running.load(.acquire)) {
            const now_ns: u64 = @intCast(std.time.nanoTimestamp());
            // Drive discv5 (inbound packet dispatch + timeout expiry + bucket refresh).
            _ = self.discv5.poll(now_ns);
            // Drive peer warmup scheduling + QUIC dial flushes.
            // Pass slot_offset_ms in the idle window so warmup always triggers.
            self.manager.poll(now_ns, peering_warmup_mod.phase_idle_start_ms);
            std.Thread.sleep(POLL_INTERVAL_NS);
        }
    }

    /// `PeerManager.on_peer_dialed` callback: convert NodeId → hex peer ID string,
    /// then dispatch `onPeerConnected` to all registered handlers.
    fn onPeerDialedCb(ctx: ?*anyopaque, node_id: [32]u8, addr: std.net.Address) void {
        const self: *Self = @ptrCast(@alignCast(ctx.?));
        _ = addr;

        const peer_id_hex = std.fmt.bytesToHex(node_id, .lower);
        const peer_id: []const u8 = &peer_id_hex;

        self.peer_event_handler.onPeerConnected(peer_id, .outbound) catch |err| {
            self.logger.err(
                "network-{d}:: onPeerConnected dispatch failed for peer={s}: {any}",
                .{ self.params.networkId, peer_id, err },
            );
        };
    }

    fn subscribePeerEventsFn(ptr: *anyopaque, handler: interface.OnPeerEventCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.peer_event_handler.subscribe(handler);
    }

    pub fn getPeerEvents(self: *Self) interface.PeerEvents {
        return .{
            .ptr = self,
            .subscribeFn = subscribePeerEventsFn,
        };
    }

    /// Hex-encoded local NodeId string (64 chars).
    /// Use this as `local_peer_id` when constructing `EthP2PNetworkParams`.
    pub fn localNodeIdHex(self: *const Self, buf: *[64]u8) []const u8 {
        const hex = std.fmt.bytesToHex(self.discv5.local_id, .lower);
        @memcpy(buf, &hex);
        return buf;
    }
};
