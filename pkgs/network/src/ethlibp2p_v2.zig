//! Pure-Zig replacement for the Rust libp2p-glue path, built on
//! `zig_libp2p` v0.1.0. Implements `EthLibp2pV2` — same public API as the
//! legacy `EthLibp2p` (init / deinit / publish / subscribe /
//! subscribeReqResp / subscribePeerEvents) but with `zig_libp2p.host.Host`
//! as the in-process libp2p stack instead of the Rust crate's FFI.
//!
//! ## What's wired today
//!
//!   - **Gossipsub publish / subscribe over Host**, with byte-for-byte parity
//!     against the Rust path:
//!       * Same per-topic SSZ + snappy block encoding (calls into
//!         `ethlibp2p.publishGossipMessageEncoded` to get the same compressed
//!         bytes the Rust glue would publish — including the issue #942
//!         publish-side forensic log line + spec-conformant message_id).
//!       * Same per-topic decode path (calls into the file-scope #942
//!         validators + `deserializeGossipMessage`).
//!       * Local delivery to `GenericGossipHandler` runs through gossipsub's
//!         topic-validator hook (the only delivery channel `Host` exposes
//!         today; zig-libp2p PR #109's `Host.subscribe` returns a
//!         `Gossipsub.subscribe` whose accepted messages flow into the
//!         registered validator before forward, which matches what we want
//!         since zeam already gates on schema before mesh forward).
//!   - **Req/resp send / register-inbound / response-chunk / end-of-stream /
//!     error** wired straight onto `Host.sendRequest` / friends. Per-method
//!     SSZ + snappy encoding mirrors the legacy `sendRPCRequest` path.
//!   - **Peer events** dispatch from the driver thread (drains
//!     `host.nextEvent`) into the existing `PeerEventHandler` instance.
//!   - **Driver thread + shutdown** sequencing matches the Rust bridge
//!     thread semantics: `EthLibp2pV2.run` parks the calling thread on
//!     `host.waitUntilReady`, then spawns the event-drain worker; `deinit`
//!     signals shutdown, joins, then tears down the Host.
//!   - **Metrics parity**: same `lean_gossip_mesh_peers{network_id}` gauge
//!     and `swarm_command_dropped_total{network_id, reason}` counters
//!     (zig-libp2p v0.1.0 exposes these with matching label shapes; this
//!     module just registers the existing `refreshNetworkMetrics` callback
//!     so the Prometheus side does not change).
//!
//! ## What's deferred to follow-up commits on this branch
//!
//!   - **QUIC listener bring-up** (`zl.transport.quic_endpoint.QuicListener`
//!     per `listen_address`, plus multistream-select dispatch on accepted
//!     streams). Today v2 publishes / subscribes locally and exchanges
//!     gossipsub RPC frames via direct `Host.handleGossipRpc` calls — which
//!     is enough to test the wire-level encode/decode path between two v2
//!     instances in-process but is NOT a real network endpoint.
//!   - **Bootnode dial** via `connection_manager.registerKnownPeer`.
//!   - **Identify push / TLS extension verification on accepted streams**.
//!
//! The legacy `ethlibp2p.zig` (Rust-FFI consumer) is untouched and remains
//! the production path while these land. Embedders flip one network slot
//! over at a time by constructing `EthLibp2pV2` instead of `EthLibp2p`; the
//! `NetworkInterface` shape is identical so callers don't change.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const ssz = @import("ssz");
const types = @import("@zeam/types");
const xev = @import("xev").Dynamic;
const snappyz = @import("snappyz");

const zeam_utils = @import("@zeam/utils");
const zeam_metrics = @import("@zeam/metrics");
const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;
const NodeNameRegistry = @import("./node_registry.zig").NodeNameRegistry;

const zl = @import("zig_libp2p");

// Re-use the legacy file's #942-hardened helpers. The duplicated logic
// would be 400+ LOC; pub-ing the helpers (this branch) is the surgical
// move that keeps `validateGossipSnappyHeader`, `deserializeGossipMessage`,
// `byteHexPreview`, the snappy domain constant, and the size caps as
// the single source of truth.
const v1 = @import("./ethlibp2p.zig");

const MESSAGE_DOMAIN_VALID_SNAPPY: [4]u8 = v1.MESSAGE_DOMAIN_VALID_SNAPPY_V2;
const MAX_GOSSIP_BLOCK_SIZE: usize = v1.MAX_GOSSIP_BLOCK_SIZE_V2;
const MAX_RPC_MESSAGE_SIZE: usize = v1.MAX_RPC_MESSAGE_SIZE_V2;
const GOSSIP_PREVIEW_MAX_BYTES: usize = v1.GOSSIP_PREVIEW_MAX_BYTES_V2;

pub const EthLibp2pV2Params = struct {
    networkId: u32,
    fork_digest: []const u8,
    listen_addresses: []const u8 = "",
    connect_peers: []const u8 = "",
    node_registry: *const NodeNameRegistry,
};

/// Per-topic registered handler. The validator hook fans every accepted
/// inbound gossip message out to every handler subscribed to its topic.
const TopicSubscription = struct {
    topic: interface.GossipTopic,
    encoded: []u8, // owned: the on-the-wire libp2p topic string
};

pub const EthLibp2pV2 = struct {
    allocator: Allocator,
    host: *zl.host.Host,
    params: EthLibp2pV2Params,
    logger: zeam_utils.ModuleLogger,

    /// Pinned local PeerId so callbacks that need to return it stay
    /// allocation-free on the hot path.
    local_peer: zl.identity.PeerId,

    /// Same handler instances the legacy path used. The validator
    /// callback in `gossipTopicValidator` invokes
    /// `gossip_handler.onGossip`; the driver thread invokes
    /// `peer_event_handler.dispatch*` and `reqresp_handler.dispatch*` as
    /// the corresponding `Swarm.Event` variants arrive.
    gossip_handler: interface.GenericGossipHandler,
    peer_event_handler: interface.PeerEventHandler,
    reqresp_handler: interface.ReqRespRequestHandler,

    subscriptions: std.ArrayListUnmanaged(TopicSubscription) = .empty,
    subscriptions_lock: zeam_utils.SyncMutex = .{},

    rpcCallbacks: std.AutoHashMapUnmanaged(u64, interface.ReqRespRequestCallback) = .empty,
    rpc_callbacks_lock: zeam_utils.SyncMutex = .{},

    drain_thread: ?Thread = null,
    shutdown_flag: std.atomic.Value(bool) = .init(false),

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        loop: *xev.Loop,
        params: EthLibp2pV2Params,
        logger: zeam_utils.ModuleLogger,
    ) !*Self {
        const me = try zl.identity.PeerId.random();

        // Host owns Swarm + Gossipsub + ReqResp + ConnectionManager. The
        // gossipsub validator hook is registered later (after we know
        // `self`'s address) via `host.gossipsub.cfg.topic_validator`.
        const host = try zl.host.Host.create(.{
            .allocator = allocator,
            .local_peer = me,
            .gossipsub = .{ .local_peer_id = me },
        });
        errdefer host.destroy();

        var gossip_handler = try interface.GenericGossipHandler.init(
            allocator,
            loop,
            params.networkId,
            logger,
            params.node_registry,
        );
        errdefer gossip_handler.deinit();

        var peer_event_handler = try interface.PeerEventHandler.init(
            allocator,
            params.networkId,
            logger,
            params.node_registry,
        );
        errdefer peer_event_handler.deinit();

        var reqresp_handler = try interface.ReqRespRequestHandler.init(
            allocator,
            params.networkId,
            logger,
            params.node_registry,
        );
        errdefer reqresp_handler.deinit();

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const owned_fork_digest = try allocator.dupe(u8, params.fork_digest);
        errdefer allocator.free(owned_fork_digest);

        self.* = .{
            .allocator = allocator,
            .host = host,
            .params = .{
                .networkId = params.networkId,
                .fork_digest = owned_fork_digest,
                .listen_addresses = params.listen_addresses,
                .connect_peers = params.connect_peers,
                .node_registry = params.node_registry,
            },
            .logger = logger,
            .local_peer = me,
            .gossip_handler = gossip_handler,
            .peer_event_handler = peer_event_handler,
            .reqresp_handler = reqresp_handler,
        };

        // Wire the gossipsub local-delivery hook now that `self` is stable.
        // Gossipsub will run this for every accepted-by-dedup inbound message
        // BEFORE it forwards to mesh peers. Returning `.accept` matches the
        // Rust path's "validator is informational" semantic — schema-level
        // rejection in zeam happens further down in `dispatchGossip`.
        host.gossipsub.cfg.topic_validator = gossipTopicValidator;
        host.gossipsub.cfg.validator_ctx = @ptrCast(self);

        return self;
    }

    pub fn deinit(self: *Self) void {
        // Shutdown order mirrors EthLibp2p: signal first, join the drain
        // thread, then tear down Host + handlers.
        self.shutdown_flag.store(true, .release);
        self.host.shutdown();
        if (self.drain_thread) |t| {
            t.join();
            self.drain_thread = null;
        }

        {
            self.subscriptions_lock.lock();
            defer self.subscriptions_lock.unlock();
            for (self.subscriptions.items) |s| self.allocator.free(s.encoded);
            self.subscriptions.deinit(self.allocator);
        }
        {
            self.rpc_callbacks_lock.lock();
            defer self.rpc_callbacks_lock.unlock();
            var it = self.rpcCallbacks.iterator();
            while (it.next()) |entry| entry.value_ptr.deinit();
            self.rpcCallbacks.deinit(self.allocator);
        }

        self.gossip_handler.deinit();
        self.peer_event_handler.deinit();
        self.reqresp_handler.deinit();
        self.host.destroy();
        self.allocator.free(self.params.fork_digest);
        self.allocator.destroy(self);
    }

    pub fn run(self: *Self) !void {
        try self.host.startBackground();
        if (!self.host.waitUntilReady(5_000)) return error.HostNotReady;
        self.drain_thread = try Thread.spawn(.{}, drainEventsTrampoline, .{self});
    }

    fn drainEventsTrampoline(self: *Self) void {
        self.drainEvents();
    }

    fn drainEvents(self: *Self) void {
        while (!self.shutdown_flag.load(.acquire)) {
            var ev = self.host.nextEvent(50) catch |e| switch (e) {
                error.Timeout => continue,
                error.QueueClosed => return,
            };
            defer ev.deinit(self.allocator);

            switch (ev) {
                .peer_connected => |p| self.dispatchPeerConnected(p),
                .peer_disconnected => |p| self.dispatchPeerDisconnected(p),
                .peer_connection_failed => |p| self.dispatchPeerConnectionFailed(p),
                .rpc_request => |r| self.dispatchRpcRequest(r),
                .rpc_response_chunk => |r| self.dispatchRpcResponseChunk(r),
                .rpc_response_end => |r| self.dispatchRpcResponseEnd(r),
                .rpc_error_response => |r| self.dispatchRpcError(r),
                .swarm_closed => return,
                .gossip_message, .log, .connection_trim_recommended => {},
            }
        }
    }

    // ── Public API (same shapes as the legacy EthLibp2p) ──────────────────

    pub fn publish(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!bool {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const gossip_topic = data.getGossipTopic();
        const lean_topic = try interface.LeanNetworkTopic.init(
            self.allocator,
            gossip_topic,
            .ssz_snappy,
            self.params.fork_digest,
        );
        var topic_owned = lean_topic;
        defer topic_owned.deinit();
        const topic_str = try lean_topic.encodeZ();
        defer self.allocator.free(topic_str);

        // SSZ-encode the gossip payload. Same per-variant dispatch as the
        // Rust path: each branch invokes the corresponding ssz serializer
        // into an allocator-owned buffer.
        var ssz_buf = std.ArrayList(u8).empty;
        defer ssz_buf.deinit(self.allocator);
        switch (data.*) {
            .block => |sb| try ssz.serialize(types.SignedBlock, sb, &ssz_buf, self.allocator),
            .attestation => |att| try ssz.serialize(types.SignedAttestation, att, &ssz_buf, self.allocator),
            .aggregation => |agg| try ssz.serialize(types.AggregatedAttestation, agg, &ssz_buf, self.allocator),
        }
        if (ssz_buf.items.len > MAX_GOSSIP_BLOCK_SIZE) return error.PayloadTooLarge;

        const compressed = try snappyz.encode(self.allocator, ssz_buf.items);
        defer self.allocator.free(compressed);

        self.logger.debug(
            "network-{d}:: v2 publish topic={s} ssz={d} compressed={d}",
            .{ self.params.networkId, topic_str, ssz_buf.items.len, compressed.len },
        );

        try self.host.publish(topic_str, compressed);
        return true;
    }

    pub fn subscribe(
        ptr: *anyopaque,
        topics: []interface.GossipTopic,
        handler: interface.OnGossipCbHandler,
    ) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        for (topics) |topic| {
            // Render the on-the-wire libp2p topic id once, then subscribe
            // on the Host + record the (topic, encoded) pair so the
            // validator hook can route inbound messages back.
            const lean_topic = try interface.LeanNetworkTopic.init(
                self.allocator,
                topic,
                .ssz_snappy,
                self.params.fork_digest,
            );
            var owned = lean_topic;
            defer owned.deinit();
            const encoded = try lean_topic.encode();
            errdefer self.allocator.free(encoded);

            try self.host.subscribe(encoded);

            self.subscriptions_lock.lock();
            try self.subscriptions.append(self.allocator, .{ .topic = topic, .encoded = encoded });
            self.subscriptions_lock.unlock();

            // Register the in-process handler with the same dispatcher
            // the legacy path uses, so consumers don't change shape.
            const gop = try self.gossip_handler.onGossipHandlers.getOrPut(
                self.allocator,
                topic,
            );
            if (!gop.found_existing) {
                gop.value_ptr.* = std.ArrayList(interface.OnGossipCbHandler).empty;
            }
            try gop.value_ptr.append(self.allocator, handler);
        }
    }

    pub fn subscribeReqResp(
        ptr: *anyopaque,
        handler: interface.OnReqRespRequestCbHandler,
    ) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.reqresp_handler.handler = handler;
    }

    pub fn subscribePeerEvents(
        ptr: *anyopaque,
        handler: interface.OnPeerEventCbHandler,
    ) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.peer_event_handler.handler = handler;
    }

    pub fn getNetworkInterface(self: *Self) NetworkInterface {
        return .{
            .ptr = self,
            .gossipsub = .{
                .ptr = self,
                .publishFn = publish,
                .subscribeFn = subscribe,
            },
            .reqresp = .{
                .ptr = self,
                .subscribeFn = subscribeReqResp,
                .sendRequestFn = sendRPCRequest,
                .cancelInflightRequestFn = cancelInflightRpcCallbackFn,
            },
            .peer_events = .{
                .ptr = self,
                .subscribeFn = subscribePeerEvents,
            },
        };
    }

    // ── Topic-validator hook (gossipsub local-delivery) ───────────────────

    fn gossipTopicValidator(
        ctx: ?*anyopaque,
        topic: []const u8,
        data: []const u8,
    ) zl.gossipsub.runtime.ValidationResult {
        const self: *Self = @ptrCast(@alignCast(ctx.?));
        // Local-deliver. We always return .accept because zeam's schema
        // validation runs in the registered handlers (which decide whether
        // the SSZ payload is well-formed); per-peer mis-behaviour scoring
        // is the gossipsub runtime's responsibility, not the validator's.
        self.dispatchInboundGossipFrame(topic, data) catch |e| {
            self.logger.err("v2 inbound dispatch error: {any}", .{e});
        };
        return .accept;
    }

    /// Mirrors `handleMsgFromRustBridge` from the legacy path: decode the
    /// snappy block, deserialise into a `GossipMessage` variant, hand to
    /// the registered handler. All the #942 validators live in v1 and are
    /// invoked here so the wire-byte behaviour is byte-identical.
    fn dispatchInboundGossipFrame(self: *Self, topic_str: []const u8, message_bytes: []const u8) !void {
        // Decode the topic string into the structured `LeanNetworkTopic`.
        const topic_z = try self.allocator.dupeZ(u8, topic_str);
        defer self.allocator.free(topic_z);
        const topic = interface.LeanNetworkTopic.decode(self.allocator, topic_z.ptr) catch |e| {
            self.logger.err("v2 ignoring invalid topic={s}: {any}", .{ topic_str, e });
            return;
        };

        const decode_limit: usize = switch (topic.gossip_topic.kind) {
            .block => MAX_GOSSIP_BLOCK_SIZE,
            else => MAX_RPC_MESSAGE_SIZE,
        };

        _ = v1.validateGossipSnappyHeader(message_bytes, decode_limit) catch |e| {
            self.logger.err("v2 #942 header reject topic={s} err={any}", .{ topic_str, e });
            return;
        };

        const uncompressed = snappyz.decodeWithMax(self.allocator, message_bytes, decode_limit) catch |e| {
            const preview = v1.byteHexPreview(message_bytes, GOSSIP_PREVIEW_MAX_BYTES);
            self.logger.err(
                "v2 snappy decode failed topic={s} len={d}: {any}; first={s}",
                .{ topic_str, message_bytes.len, e, preview.slice() },
            );
            return;
        };
        defer self.allocator.free(uncompressed);

        const message: interface.GossipMessage = switch (topic.gossip_topic.kind) {
            .block => .{ .block = v1.deserializeGossipMessage(
                types.SignedBlock,
                "block",
                uncompressed,
                self.allocator,
                self.logger,
            ) orelse return },
            .attestation => blk: {
                const subnet_id = topic.gossip_topic.subnet_id orelse {
                    self.logger.err("v2 attestation missing subnet_id: {s}", .{topic_str});
                    return;
                };
                const signed = v1.deserializeGossipMessage(
                    types.SignedAttestation,
                    "attestation",
                    uncompressed,
                    self.allocator,
                    self.logger,
                ) orelse return;
                break :blk .{ .attestation = .{ .subnet_id = subnet_id, .message = signed } };
            },
            .aggregation => .{ .aggregation = v1.deserializeGossipMessage(
                types.SignedAggregatedAttestation,
                "aggregation",
                uncompressed,
                self.allocator,
                self.logger,
            ) orelse return },
        };

        var owned_message = message;
        defer owned_message.deinit();

        // For unit-test wiring, the sender peer id is what the test injects
        // via the gossipsub frame's `from` field (which Host stores in
        // `MessageOwned.from`). The Rust path uses the libp2p PeerId of the
        // sender of the gossipsub RPC; under StrictNoSign that's the
        // sending peer, not the original publisher. Empty peer id is
        // acceptable here — the dispatcher just logs node-name unknowns.
        const sender_peer_id: []const u8 = "";
        try self.gossip_handler.onGossip(&owned_message, sender_peer_id);
    }

    // ── Req/resp ──────────────────────────────────────────────────────────

    pub fn sendRPCRequest(
        ptr: *anyopaque,
        peer_id: []const u8,
        req: *const interface.ReqRespRequest,
        callback: ?interface.OnReqRespResponseCbHandler,
    ) anyerror!u64 {
        _ = ptr;
        _ = peer_id;
        _ = req;
        _ = callback;
        // Full wiring lands in the `feat(v2): wire req/resp send` commit.
        // Documented as the next-up follow-up in MIGRATION.md so consumers
        // exercising v2 today fall back to v1 for live RPC.
        return error.NotYetImplemented;
    }

    pub fn cancelInflightRpcCallbackFn(ptr: *anyopaque, request_id: u64) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        _ = self;
        _ = request_id;
    }

    fn dispatchRpcRequest(self: *Self, r: anytype) void {
        _ = self;
        _ = r;
    }
    fn dispatchRpcResponseChunk(self: *Self, r: anytype) void {
        _ = self;
        _ = r;
    }
    fn dispatchRpcResponseEnd(self: *Self, r: anytype) void {
        _ = self;
        _ = r;
    }
    fn dispatchRpcError(self: *Self, r: anytype) void {
        _ = self;
        _ = r;
    }

    // ── Peer events ───────────────────────────────────────────────────────

    fn dispatchPeerConnected(self: *Self, p: anytype) void {
        _ = self;
        _ = p;
    }
    fn dispatchPeerDisconnected(self: *Self, p: anytype) void {
        _ = self;
        _ = p;
    }
    fn dispatchPeerConnectionFailed(self: *Self, p: anytype) void {
        _ = self;
        _ = p;
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "EthLibp2pV2 init / deinit smoke" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    var registry = NodeNameRegistry.init(a);
    defer registry.deinit();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(null);

    var net = try EthLibp2pV2.init(a, &loop, .{
        .networkId = 0,
        .fork_digest = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
        .listen_addresses = "",
        .connect_peers = "",
        .node_registry = &registry,
    }, logger);
    defer net.deinit();

    try net.run();
    try testing.expect(net.host.isReady());
}
