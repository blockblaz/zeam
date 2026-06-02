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
//!       * Per-topic SSZ + snappy block encoding, then `host.publish`.
//!       * Per-topic decode through the file-scope #942 validators in
//!         `ethlibp2p.zig` (promoted to `pub` in this branch so v2 doesn't
//!         fork the 400 LOC of frame-hardening logic).
//!       * Local delivery to `GenericGossipHandler` runs through gossipsub's
//!         topic-validator hook (v0.1.0's only inbound channel today).
//!   - **Req/resp send / register-inbound / response-chunk / end-of-stream /
//!     error** wired straight onto `Host.sendRequest` and friends. Per-method
//!     SSZ decode (the wire layer in zig-libp2p handles snappy framing).
//!   - **Peer-event dispatch** from the driver thread (drains
//!     `host.nextEvent`) into the existing `PeerEventHandler` instance. Peer
//!     IDs are base58-multihash-encoded to match the Rust glue's
//!     `PeerId::to_string()` output exactly, so the node-name registry
//!     lookups keep matching.
//!   - **In-flight RPC failure on peer disconnect** — same defense as the
//!     legacy path: when a peer drops, every pending outbound RPC awaiting
//!     a response from that peer is failed with `error.PeerDisconnected`.
//!   - **Bootnode dial** — `connect_peers` is parsed as a comma-separated
//!     list of multiaddrs and each is registered via
//!     `host.registerKnownPeer`. The driver thread calls
//!     `connection_manager.tick(now_ms)` once per loop so dial attempts
//!     (with exponential backoff per upstream policy) get scheduled.
//!   - **Driver thread + shutdown** sequencing matches the Rust bridge
//!     thread semantics: `run` parks the calling thread on
//!     `host.waitUntilReady`, then spawns the event-drain worker; `deinit`
//!     signals shutdown, joins, then tears down the Host.
//!   - **Metrics parity**: a per-instance `Metrics` registry is wired into
//!     the Host config so gossipsub + swarm record into it. A scrape
//!     refresher copies `host.gossipsub.meshPeers()` and per-reason
//!     `swarm.metrics.?.swarmCommandDropped()` totals into zeam's
//!     `lean_gossip_mesh_peers` gauge / `zeam_libp2p_swarm_command_dropped_total`
//!     counter on every Prometheus scrape (same shape and labels the Rust
//!     glue used).
//!
//! ## What's deferred to follow-up commits on this branch
//!
//!   - **QUIC listener bring-up** (`zl.transport.quic_endpoint.QuicListener`
//!     per `listen_address`, plus multistream-select dispatch on accepted
//!     streams). Today v2 publishes / subscribes locally and exchanges
//!     gossipsub RPC frames via direct `Host.handleGossipRpc` calls — which
//!     is enough to test the wire-level encode/decode path between two v2
//!     instances in-process but is NOT a real network endpoint. Without
//!     this, the dial stub in zig-libp2p v0.1.0 reports `DialFailed`
//!     immediately for every bootnode, so the connect_peers wiring above
//!     only exercises the scheduler, not actual peer establishment.
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
const Multiaddr = @import("multiaddr").Multiaddr;

// Re-use the legacy file's #942-hardened helpers. Duplicating the logic
// would be 400+ LOC; the helpers are `pub` so `validateGossipSnappyHeader`,
// `deserializeGossipMessage`, `byteHexPreview`, the snappy domain constant,
// and the size caps stay the single source of truth.
const v1 = @import("./ethlibp2p.zig");

const MESSAGE_DOMAIN_VALID_SNAPPY: [4]u8 = v1.MESSAGE_DOMAIN_VALID_SNAPPY_V2;
const MAX_GOSSIP_BLOCK_SIZE: usize = v1.MAX_GOSSIP_BLOCK_SIZE_V2;
const MAX_RPC_MESSAGE_SIZE: usize = v1.MAX_RPC_MESSAGE_SIZE_V2;
const GOSSIP_PREVIEW_MAX_BYTES: usize = v1.GOSSIP_PREVIEW_MAX_BYTES_V2;

/// Default per-request response wait used by the legacy path (the Rust glue
/// embeds a 15s timeout in its req/resp protocol handler). zig-libp2p's
/// `Host.sendRequest` adds `request_timeout_ms` (default 15_000) onto the
/// `now_ms` value the embedder passes, so we pass the current wall time
/// directly and inherit the same 15s deadline.
const DEFAULT_REQ_TIMEOUT_NOW_MS = 0; // see commentary at `sendRPCRequest`

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
    /// Per-instance metrics registry owned by this v2. Wired into Host so
    /// gossipsub + swarm record into it; the scrape refresher reads from it.
    metrics_registry: *zl.metrics.Metrics,
    params: EthLibp2pV2Params,
    logger: zeam_utils.ModuleLogger,

    /// Pinned local PeerId so callbacks that need to return it stay
    /// allocation-free on the hot path.
    local_peer: zl.identity.PeerId,

    /// Same handler instances the legacy path used. The validator
    /// callback in `gossipTopicValidator` invokes
    /// `gossip_handler.onGossip`; the driver thread invokes
    /// `peer_event_handler.onPeer*` and `reqresp_handler.onReqRespRequest`
    /// as the corresponding `Swarm.Event` variants arrive.
    gossip_handler: interface.GenericGossipHandler,
    peer_event_handler: interface.PeerEventHandler,
    reqresp_handler: interface.ReqRespRequestHandler,

    subscriptions: std.ArrayListUnmanaged(TopicSubscription) = .empty,
    subscriptions_lock: zeam_utils.SyncMutex = .{},

    rpc_callbacks: std.AutoHashMapUnmanaged(u64, interface.ReqRespRequestCallback) = .empty,
    rpc_callbacks_lock: zeam_utils.SyncMutex = .{},

    /// Last-seen swarm-drop totals per reason, indexed by
    /// `@intFromEnum(zl.metrics.SwarmDropReason)`. The scrape refresher
    /// computes `current - last_seen` and calls `incrBy` with the delta,
    /// then updates this baseline. Same delta-on-scrape semantic as the
    /// legacy Rust path.
    swarm_drop_last_seen: [3]u64 = .{ 0, 0, 0 },

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

        const metrics_registry = try allocator.create(zl.metrics.Metrics);
        errdefer allocator.destroy(metrics_registry);
        metrics_registry.* = .{};

        // Host owns Swarm + Gossipsub + ReqResp + ConnectionManager. The
        // gossipsub validator hook is registered later (after we know
        // `self`'s address) via `host.gossipsub.cfg.topic_validator`.
        const host = try zl.host.Host.create(.{
            .allocator = allocator,
            .local_peer = me,
            .metrics = metrics_registry,
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
            .metrics_registry = metrics_registry,
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
        // Gossipsub runs this for every accepted-by-dedup inbound message
        // BEFORE forwarding to mesh peers. We always return `.accept` because
        // zeam's schema validation runs in the registered handlers (which
        // decide whether the SSZ payload is well-formed); per-peer
        // mis-behaviour scoring is the gossipsub runtime's job, not the
        // validator's.
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
            var it = self.rpc_callbacks.iterator();
            while (it.next()) |entry| entry.value_ptr.deinit();
            self.rpc_callbacks.deinit(self.allocator);
        }

        self.gossip_handler.deinit();
        self.peer_event_handler.deinit();
        self.reqresp_handler.deinit();
        self.host.destroy();
        self.allocator.destroy(self.metrics_registry);
        self.allocator.free(self.params.fork_digest);
        self.allocator.destroy(self);
    }

    pub fn run(self: *Self) !void {
        try self.host.startBackground();
        if (!self.host.waitUntilReady(5_000)) return error.HostNotReady;

        // Register bootnodes now that the host is running. Without a real
        // transport (deferred) every dial will fail-stub, but the
        // connection-manager scheduling + back-off semantics are exercised.
        if (self.params.connect_peers.len > 0) {
            self.registerBootnodes() catch |e| {
                self.logger.err(
                    "network-{d}:: bootnode registration failed: {any}",
                    .{ self.params.networkId, e },
                );
            };
        }

        self.drain_thread = try Thread.spawn(.{}, drainEventsTrampoline, .{self});
    }

    fn registerBootnodes(self: *Self) !void {
        var it = std.mem.tokenizeScalar(u8, self.params.connect_peers, ',');
        while (it.next()) |raw| {
            const trimmed = std.mem.trim(u8, raw, " \t\r\n");
            if (trimmed.len == 0) continue;
            const ma = Multiaddr.fromString(self.allocator, trimmed) catch |e| {
                self.logger.err(
                    "network-{d}:: invalid bootnode multiaddr {s}: {any}",
                    .{ self.params.networkId, trimmed, e },
                );
                continue;
            };
            defer ma.deinit();
            self.host.registerKnownPeer(&ma, null) catch |e| {
                self.logger.err(
                    "network-{d}:: registerKnownPeer({s}) failed: {any}",
                    .{ self.params.networkId, trimmed, e },
                );
                continue;
            };
            self.logger.info(
                "network-{d}:: registered bootnode {s}",
                .{ self.params.networkId, trimmed },
            );
        }
    }

    fn drainEventsTrampoline(self: *Self) void {
        self.drainEvents();
    }

    fn drainEvents(self: *Self) void {
        while (!self.shutdown_flag.load(.acquire)) {
            // Drive the connection-manager scheduler so registered known
            // peers actually get dialed (and re-dialed on back-off).
            const now_ms = zl.wall_time.milliTimestamp();
            self.host.connection_manager.tick(now_ms) catch |e| {
                self.logger.err(
                    "network-{d}:: connection_manager.tick failed: {any}",
                    .{ self.params.networkId, e },
                );
            };

            // Republish the gossipsub mesh-peer total into the per-instance
            // metrics registry so the scrape refresher sees a fresh value
            // even when no swarm events are flowing.
            self.metrics_registry.setMeshPeers(self.host.gossipsub.meshPeers());

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
        try self.reqresp_handler.subscribe(handler);
    }

    pub fn subscribePeerEvents(
        ptr: *anyopaque,
        handler: interface.OnPeerEventCbHandler,
    ) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        try self.peer_event_handler.subscribe(handler);
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

        const sender_peer_id: []const u8 = "";
        try self.gossip_handler.onGossip(&owned_message, sender_peer_id);
    }

    // ── Req/resp ──────────────────────────────────────────────────────────

    /// Serialise the typed request via SSZ, ship it to `host.sendRequest`
    /// (whose wire layer applies the per-spec varint-uncompressed-size +
    /// snappy framing), and stash the response callback under the returned
    /// `request_id`. The callback is freed when the stream completes
    /// (`rpc_response_end` / `rpc_error_response`) or when the peer
    /// disconnects (`failInflightRpcsForPeer`).
    pub fn sendRPCRequest(
        ptr: *anyopaque,
        peer_id: []const u8,
        req: *const interface.ReqRespRequest,
        callback: ?interface.OnReqRespResponseCbHandler,
    ) anyerror!u64 {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const peer = try zl.identity.PeerId.fromString(self.allocator, peer_id);

        // Convert zeam's LeanSupportedProtocol → zig-libp2p's. The two enums
        // share discriminants (asserted in `comptime_protocol_alignment` test
        // below), so a direct int round-trip is safe.
        const proto: zl.protocol.LeanSupportedProtocol = blk: {
            const tag: u32 = @intFromEnum(@as(interface.LeanSupportedProtocol, req.*));
            break :blk zl.protocol.LeanSupportedProtocol.fromInt(tag) orelse return error.UnknownProtocol;
        };

        const ssz_bytes = try req.serialize(self.allocator);
        defer self.allocator.free(ssz_bytes);

        // `Host.sendRequest`'s `timeout_ms` argument is forwarded as `now_ms`
        // into the req/resp runtime, which adds `request_timeout_ms`
        // (15s default) to compute the request deadline. Pass the current
        // wall time so the deadline lands 15s in the real future.
        const now_ms = zl.wall_time.milliTimestamp();
        const request_id = try self.host.sendRequest(
            peer,
            proto,
            ssz_bytes,
            @intCast(@as(u64, @bitCast(now_ms))),
        );

        if (callback) |handler| {
            const peer_id_copy = try self.allocator.dupe(u8, peer_id);
            errdefer self.allocator.free(peer_id_copy);
            const method: interface.LeanSupportedProtocol = @enumFromInt(@intFromEnum(req.*));
            var entry = interface.ReqRespRequestCallback.init(method, self.allocator, handler, peer_id_copy);
            self.putRpcCallback(request_id, entry) catch |e| {
                entry.deinit();
                return e;
            };
        }

        self.logger.debug(
            "network-{d}:: v2 sendRPCRequest peer={s} method={s} request_id={d} ssz_len={d}",
            .{ self.params.networkId, peer_id, @tagName(proto), request_id, ssz_bytes.len },
        );

        return request_id;
    }

    pub fn cancelInflightRpcCallbackFn(ptr: *anyopaque, request_id: u64) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (self.takeRpcCallback(request_id)) |cb| {
            var owned = cb;
            owned.deinit();
        }
    }

    fn putRpcCallback(self: *Self, request_id: u64, cb: interface.ReqRespRequestCallback) !void {
        self.rpc_callbacks_lock.lock();
        defer self.rpc_callbacks_lock.unlock();
        try self.rpc_callbacks.put(self.allocator, request_id, cb);
    }

    fn takeRpcCallback(self: *Self, request_id: u64) ?interface.ReqRespRequestCallback {
        self.rpc_callbacks_lock.lock();
        defer self.rpc_callbacks_lock.unlock();
        if (self.rpc_callbacks.fetchRemove(request_id)) |kv| return kv.value;
        return null;
    }

    /// Snapshot a registered callback (peer_id duped) without removing it —
    /// for streaming responses where additional chunks may still arrive.
    /// Returns `null` if no callback is registered for the request_id.
    fn snapshotRpcCallback(self: *Self, request_id: u64) ?CallbackSnapshot {
        self.rpc_callbacks_lock.lock();
        defer self.rpc_callbacks_lock.unlock();
        const cb = self.rpc_callbacks.get(request_id) orelse return null;
        // Caller does not need the peer_id copy, only the method + handler.
        return .{
            .method = cb.method,
            .handler = cb.handler,
        };
    }

    const CallbackSnapshot = struct {
        method: interface.LeanSupportedProtocol,
        handler: ?interface.OnReqRespResponseCbHandler,
    };

    /// Inbound RPC request: zig-libp2p has already unframed snappy and
    /// surfaced the raw SSZ payload to us. Register an inbound channel so
    /// we can route responses back, wrap it in a `ReqRespServerStream`,
    /// and hand the typed request to the registered handler.
    fn dispatchRpcRequest(self: *Self, r: zl.swarm.RpcRequest) void {
        // Translate zig-libp2p protocol enum → zeam interface enum (same
        // discriminants — asserted in tests).
        const method: interface.LeanSupportedProtocol = mapInboundProtocol(r.protocol) orelse {
            self.logger.err(
                "network-{d}:: v2 inbound rpc unknown protocol tag={d}",
                .{ self.params.networkId, @intFromEnum(r.protocol) },
            );
            return;
        };

        // Stringify the peer id for the handler / node-name registry.
        var peer_buf: [128]u8 = undefined;
        const peer_str = r.peer.toBase58(&peer_buf) catch |e| {
            self.logger.err(
                "network-{d}:: v2 inbound rpc peer_id encode failed: {any}",
                .{ self.params.networkId, e },
            );
            return;
        };
        const peer_owned = self.allocator.dupe(u8, peer_str) catch |e| {
            self.logger.err(
                "network-{d}:: v2 inbound rpc OOM duping peer_id: {any}",
                .{ self.params.networkId, e },
            );
            return;
        };
        errdefer self.allocator.free(peer_owned);

        var request = interface.ReqRespRequest.deserialize(self.allocator, method, r.payload) catch |e| {
            self.logger.err(
                "network-{d}:: v2 inbound rpc SSZ decode method={s} from={s} failed: {any}",
                .{ self.params.networkId, @tagName(method), peer_str, e },
            );
            self.allocator.free(peer_owned);
            return;
        };
        defer request.deinit();

        const stream_ctx = self.allocator.create(ServerStreamContext) catch |e| {
            self.logger.err(
                "network-{d}:: v2 inbound rpc OOM allocating stream context: {any}",
                .{ self.params.networkId, e },
            );
            self.allocator.free(peer_owned);
            return;
        };
        stream_ctx.* = .{
            .parent = self,
            .channel_id = r.channel_id,
            .peer_id = peer_owned,
            .method = method,
            .finished = false,
        };

        const stream: interface.ReqRespServerStream = .{
            .ptr = stream_ctx,
            .sendResponseFn = serverStreamSendResponse,
            .sendErrorFn = serverStreamSendError,
            .finishFn = serverStreamFinish,
            .isFinishedFn = serverStreamIsFinished,
            .getPeerIdFn = serverStreamGetPeerId,
        };

        // ReqRespRequestHandler.onReqRespRequest fans out to every
        // subscribed handler and breaks early once the stream is finished.
        // Handler may retain the stream context; ownership transferred.
        self.reqresp_handler.onReqRespRequest(&request, stream) catch |e| {
            self.logger.err(
                "network-{d}:: v2 inbound rpc handler error method={s} from={s}: {any}",
                .{ self.params.networkId, @tagName(method), peer_str, e },
            );
        };

        // Auto-finish if the handler didn't explicitly close the stream;
        // matches the legacy behaviour (no leaked channels on incomplete
        // server handlers).
        if (!stream_ctx.finished) {
            serverStreamFinish(stream_ctx) catch |e| {
                self.logger.err(
                    "network-{d}:: v2 inbound rpc auto-finish failed: {any}",
                    .{ self.params.networkId, e },
                );
            };
        }
        self.allocator.free(stream_ctx.peer_id);
        self.allocator.destroy(stream_ctx);
    }

    fn dispatchRpcResponseChunk(self: *Self, r: zl.swarm.RpcResponseChunk) void {
        const snap = self.snapshotRpcCallback(r.request_id) orelse {
            // No callback registered — request was either cancelled or
            // already completed. Drop the chunk silently to match the
            // legacy path.
            return;
        };
        const handler = snap.handler orelse return;

        const response = interface.ReqRespResponse.deserialize(self.allocator, snap.method, r.chunk) catch |e| {
            self.logger.err(
                "network-{d}:: v2 response chunk decode method={s} request_id={d}: {any}",
                .{ self.params.networkId, @tagName(snap.method), r.request_id, e },
            );
            return;
        };

        var event = interface.ReqRespResponseEvent.initSuccess(r.request_id, snap.method, response);
        defer event.deinit(self.allocator);
        handler.onReqRespResponse(&event) catch |e| {
            self.logger.err(
                "network-{d}:: v2 response chunk notify request_id={d}: {any}",
                .{ self.params.networkId, r.request_id, e },
            );
        };
    }

    fn dispatchRpcResponseEnd(self: *Self, r: zl.swarm.RpcResponseEnd) void {
        var cb = self.takeRpcCallback(r.request_id) orelse return;
        defer cb.deinit();
        var event = interface.ReqRespResponseEvent.initCompleted(r.request_id, cb.method);
        cb.notify(&event) catch |e| {
            self.logger.err(
                "network-{d}:: v2 response end notify request_id={d}: {any}",
                .{ self.params.networkId, r.request_id, e },
            );
        };
    }

    fn dispatchRpcError(self: *Self, r: zl.swarm.RpcError) void {
        var cb = self.takeRpcCallback(r.request_id) orelse return;
        defer cb.deinit();
        const message = self.allocator.dupe(u8, @errorName(r.kind)) catch |e| {
            self.logger.err(
                "network-{d}:: v2 response error OOM duping message: {any}",
                .{ self.params.networkId, e },
            );
            return;
        };
        var event = interface.ReqRespResponseEvent.initError(
            r.request_id,
            cb.method,
            .{ .code = 1, .message = message },
        );
        defer event.deinit(self.allocator);
        cb.notify(&event) catch |e| {
            self.logger.err(
                "network-{d}:: v2 response error notify request_id={d}: {any}",
                .{ self.params.networkId, r.request_id, e },
            );
        };
    }

    /// Fail every in-flight outbound RPC whose target peer is `peer_id`.
    /// Called when a peer disconnects, so consumers don't block waiting
    /// for responses that will never arrive. Matches the legacy
    /// `failInflightRpcsForPeer` defense.
    fn failInflightRpcsForPeer(self: *Self, peer_id: []const u8) void {
        var to_fail: std.ArrayListUnmanaged(u64) = .empty;
        defer to_fail.deinit(self.allocator);

        {
            self.rpc_callbacks_lock.lock();
            defer self.rpc_callbacks_lock.unlock();
            var it = self.rpc_callbacks.iterator();
            while (it.next()) |entry| {
                if (std.mem.eql(u8, entry.value_ptr.peer_id, peer_id)) {
                    to_fail.append(self.allocator, entry.key_ptr.*) catch {
                        // OOM during snapshot — best-effort: skip and let
                        // the next callback removal drive eventual cleanup.
                        return;
                    };
                }
            }
        }

        for (to_fail.items) |request_id| {
            var cb = self.takeRpcCallback(request_id) orelse continue;
            defer cb.deinit();
            const message = self.allocator.dupe(u8, "peer disconnected") catch continue;
            var event = interface.ReqRespResponseEvent.initError(
                request_id,
                cb.method,
                .{ .code = 1, .message = message },
            );
            defer event.deinit(self.allocator);
            cb.notify(&event) catch |e| {
                self.logger.err(
                    "network-{d}:: v2 failInflightRpcsForPeer notify request_id={d}: {any}",
                    .{ self.params.networkId, request_id, e },
                );
            };
        }
    }

    // ── Peer events ───────────────────────────────────────────────────────

    fn dispatchPeerConnected(self: *Self, p: zl.peer_events.PeerConnectedPayload) void {
        var buf: [128]u8 = undefined;
        const peer_str = p.peer.toBase58(&buf) catch |e| {
            self.logger.err("network-{d}:: peer_connected toBase58 failed: {any}", .{ self.params.networkId, e });
            return;
        };
        const direction = mapDirection(p.direction);
        self.peer_event_handler.onPeerConnected(peer_str, direction) catch |e| {
            self.logger.err("network-{d}:: v2 onPeerConnected handler error: {any}", .{ self.params.networkId, e });
        };
    }

    fn dispatchPeerDisconnected(self: *Self, p: zl.peer_events.PeerDisconnectedPayload) void {
        var buf: [128]u8 = undefined;
        const peer_str = p.peer.toBase58(&buf) catch |e| {
            self.logger.err("network-{d}:: peer_disconnected toBase58 failed: {any}", .{ self.params.networkId, e });
            return;
        };
        self.failInflightRpcsForPeer(peer_str);
        const direction = mapDirection(p.direction);
        const reason = mapDisconnectReason(p.reason);
        self.peer_event_handler.onPeerDisconnected(peer_str, direction, reason) catch |e| {
            self.logger.err("network-{d}:: v2 onPeerDisconnected handler error: {any}", .{ self.params.networkId, e });
        };
    }

    fn dispatchPeerConnectionFailed(self: *Self, p: zl.peer_events.PeerConnectionFailedPayload) void {
        var buf: [128]u8 = undefined;
        const peer_str: []const u8 = if (p.peer) |peer| (peer.toBase58(&buf) catch {
            self.logger.err("network-{d}:: peer_connection_failed toBase58 failed", .{self.params.networkId});
            return;
        }) else "unknown";
        const direction = mapDirection(p.direction);
        const result: interface.ConnectionResult = switch (p.result) {
            .timeout => .timeout,
            .err => .error_,
        };
        self.peer_event_handler.onPeerConnectionFailed(peer_str, direction, result) catch |e| {
            self.logger.err("network-{d}:: v2 onPeerConnectionFailed handler error: {any}", .{ self.params.networkId, e });
        };
    }

    // ── Metrics scrape refresher ──────────────────────────────────────────

    /// Per-instance scrape refresher registered via
    /// `zeam_metrics.registerScrapeRefresherCtx`. Copies the per-instance
    /// metrics registry's current state into zeam's global gauge/counter,
    /// computing deltas for the monotonic swarm-drop counters.
    pub fn refreshMetrics(ctx: ?*anyopaque) void {
        if (ctx == null) return;
        const self: *Self = @ptrCast(@alignCast(ctx.?));

        // Mesh peers gauge. With multiple v2 instances, last-write-wins —
        // same caveat as the legacy path's single-`set` semantics.
        zeam_metrics.metrics.lean_gossip_mesh_peers.set(self.metrics_registry.meshPeers());

        // Swarm-drop counter — delta-on-scrape per reason.
        inline for (.{
            zl.metrics.SwarmDropReason.full,
            zl.metrics.SwarmDropReason.closed,
            zl.metrics.SwarmDropReason.uninitialized,
        }) |reason| {
            const idx: usize = @intFromEnum(reason);
            const current = self.metrics_registry.swarmCommandDropped(reason);
            const last = self.swarm_drop_last_seen[idx];
            if (current > last) {
                const delta = current - last;
                zeam_metrics.metrics.zeam_libp2p_swarm_command_dropped_total.incrBy(
                    .{ .reason = @tagName(reason) },
                    delta,
                ) catch {};
                self.swarm_drop_last_seen[idx] = current;
            }
        }
    }
};

// ── Direction / reason mapping ──────────────────────────────────────────────

/// Zig-libp2p protocol enum → zeam interface enum. The two share
/// discriminants (tested), but the interface side has no `fromInt`
/// constructor, so we keep this single mapping point and guard against a
/// future discriminant drift on either side.
fn mapInboundProtocol(p: zl.protocol.LeanSupportedProtocol) ?interface.LeanSupportedProtocol {
    return switch (p) {
        .blocks_by_root => .blocks_by_root,
        .status => .status,
        .blocks_by_range => .blocks_by_range,
    };
}

fn mapDirection(d: zl.peer_events.Direction) interface.PeerDirection {
    return switch (d) {
        .inbound => .inbound,
        .outbound => .outbound,
        .unknown => .unknown,
    };
}

fn mapDisconnectReason(r: zl.peer_events.DisconnectReason) interface.DisconnectionReason {
    return switch (r) {
        .timeout => .timeout,
        .remote_close => .remote_close,
        .local_close => .local_close,
        .err => .error_,
    };
}

// ── Server-stream context (outbound responses to inbound RPCs) ─────────────

const ServerStreamContext = struct {
    parent: *EthLibp2pV2,
    channel_id: u64,
    peer_id: []const u8,
    method: interface.LeanSupportedProtocol,
    finished: bool,
};

fn serverStreamGetPeerId(ptr: *anyopaque) ?[]const u8 {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    return ctx.peer_id;
}

fn serverStreamIsFinished(ptr: *anyopaque) bool {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    return ctx.finished;
}

fn serverStreamSendResponse(ptr: *anyopaque, response: *const interface.ReqRespResponse) anyerror!void {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    if (ctx.finished) return error.StreamFinished;

    const ssz_bytes = try response.serialize(ctx.parent.allocator);
    defer ctx.parent.allocator.free(ssz_bytes);
    const now_ms = zl.wall_time.milliTimestamp();
    try ctx.parent.host.sendResponseChunk(ctx.channel_id, ssz_bytes, now_ms);
}

fn serverStreamSendError(ptr: *anyopaque, code: u32, message: []const u8) anyerror!void {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    if (ctx.finished) return error.StreamFinished;
    _ = code;
    try ctx.parent.host.sendErrorResponse(ctx.channel_id, message);
    ctx.finished = true;
}

fn serverStreamFinish(ptr: *anyopaque) anyerror!void {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    if (ctx.finished) return;
    try ctx.parent.host.finishResponseStream(ctx.channel_id);
    ctx.finished = true;
}

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

test "EthLibp2pV2 protocol enum discriminants match zig-libp2p" {
    // Critical for the `@intFromEnum` round-trip in dispatchRpcRequest +
    // sendRPCRequest. If these ever drift, both directions of req/resp
    // routing break silently.
    try testing.expectEqual(
        @as(u32, @intFromEnum(interface.LeanSupportedProtocol.blocks_by_root)),
        @as(u32, @intFromEnum(zl.protocol.LeanSupportedProtocol.blocks_by_root)),
    );
    try testing.expectEqual(
        @as(u32, @intFromEnum(interface.LeanSupportedProtocol.status)),
        @as(u32, @intFromEnum(zl.protocol.LeanSupportedProtocol.status)),
    );
    try testing.expectEqual(
        @as(u32, @intFromEnum(interface.LeanSupportedProtocol.blocks_by_range)),
        @as(u32, @intFromEnum(zl.protocol.LeanSupportedProtocol.blocks_by_range)),
    );
}

test "EthLibp2pV2 direction mapping is total + 1:1" {
    try testing.expectEqual(interface.PeerDirection.inbound, mapDirection(.inbound));
    try testing.expectEqual(interface.PeerDirection.outbound, mapDirection(.outbound));
    try testing.expectEqual(interface.PeerDirection.unknown, mapDirection(.unknown));
}

test "EthLibp2pV2 disconnect reason mapping is total" {
    try testing.expectEqual(interface.DisconnectionReason.timeout, mapDisconnectReason(.timeout));
    try testing.expectEqual(interface.DisconnectionReason.remote_close, mapDisconnectReason(.remote_close));
    try testing.expectEqual(interface.DisconnectionReason.local_close, mapDisconnectReason(.local_close));
    try testing.expectEqual(interface.DisconnectionReason.error_, mapDisconnectReason(.err));
}

test "EthLibp2pV2 peer-event dispatch fires registered handler" {
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
        .node_registry = &registry,
    }, logger);
    defer net.deinit();

    // Subscribe a counting handler before run() so we capture both replays
    // and live events.
    const Counter = struct {
        connected: u32 = 0,
        disconnected: u32 = 0,
        failed: u32 = 0,
        var instance: @This() = .{};

        fn onConnected(_: *anyopaque, _: []const u8, _: interface.PeerDirection) anyerror!void {
            instance.connected += 1;
        }
        fn onDisconnected(_: *anyopaque, _: []const u8, _: interface.PeerDirection, _: interface.DisconnectionReason) anyerror!void {
            instance.disconnected += 1;
        }
        fn onFailed(_: *anyopaque, _: []const u8, _: interface.PeerDirection, _: interface.ConnectionResult) anyerror!void {
            instance.failed += 1;
        }
    };
    Counter.instance = .{};

    try net.peer_event_handler.subscribe(.{
        .ptr = &Counter.instance,
        .onPeerConnectedCb = Counter.onConnected,
        .onPeerDisconnectedCb = Counter.onDisconnected,
        .onPeerConnectionFailedCb = Counter.onFailed,
    });

    // Drive the dispatchers directly (no need to go through the drain
    // thread — that exercises Host.nextEvent which has its own integration
    // path; here we want the wiring assertion to be deterministic).
    const peer = try zl.identity.PeerId.random();
    net.dispatchPeerConnected(.{ .peer = peer, .direction = .outbound });
    net.dispatchPeerDisconnected(.{ .peer = peer, .direction = .outbound, .reason = .remote_close });
    net.dispatchPeerConnectionFailed(.{ .peer = peer, .direction = .outbound, .result = .timeout });

    try testing.expectEqual(@as(u32, 1), Counter.instance.connected);
    try testing.expectEqual(@as(u32, 1), Counter.instance.disconnected);
    try testing.expectEqual(@as(u32, 1), Counter.instance.failed);
}

test "EthLibp2pV2 bootnode multiaddr parsing tolerates whitespace + empty entries" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    var registry = NodeNameRegistry.init(a);
    defer registry.deinit();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(null);

    // One valid multiaddr, one invalid, one empty (after split). The
    // invalid one should log + skip without aborting; the valid one
    // should land in the connection manager's known-peer table.
    const peers = "/ip4/127.0.0.1/udp/9000/quic-v1, , not-a-multiaddr";

    var net = try EthLibp2pV2.init(a, &loop, .{
        .networkId = 0,
        .fork_digest = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
        .connect_peers = peers,
        .node_registry = &registry,
    }, logger);
    defer net.deinit();

    try net.run();
    try testing.expect(net.host.isReady());
    // The valid bootnode is registered; the failing parses log a warning
    // and continue. The connection manager's tick() in the drain thread
    // would now schedule a dial — but with v0.1.0's dial stub it'll
    // immediately fail-stub. We don't assert on dial outcome here (that
    // requires the QuicListener bring-up).
}
