//! EthP2PNetwork — Gossip via zig-ethp2p RS broadcast over QUIC.
//!                  Req/resp via zig-ethp2p QUIC bidirectional streams with SSZ+snappy framing.
//!
//! Architecture:
//!   • One RS broadcast channel per GossipTopicKind; zig-ethp2p `broadcast.Engine` owns them.
//!   • A QUIC endpoint (lsquic) listens for inbound connections.
//!   • A dedicated poll thread drives the QUIC endpoint and the RS engine.
//!   • `EthP2PDiscovery` peer-connected events trigger RS channel membership.
//!     The QUIC connection itself is dialed by `PeerManager` inside `EthP2PDiscovery`.
//!
//! Status: RS encode/decode path is wired; QUIC stream ↔ RS engine routing (SESS/CHUNK UNI
//! streams) is pending zig-ethp2p issue #27 (eth_ec_quic_peer.zig PeerConn wiring).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const zig_ethp2p = @import("zig_ethp2p");
const broadcast_engine = zig_ethp2p.broadcast.engine;
const channel_rs_mod = zig_ethp2p.broadcast.channel_rs;
const rs_init = zig_ethp2p.layer.rs_init;
const eth_ec_quic = zig_ethp2p.transport.eth_ec_quic;

const types = @import("@zeam/types");
const xev = @import("xev");
const multiformats = @import("multiformats");
const uvarint = multiformats.uvarint;
const zeam_utils = @import("@zeam/utils");
const ssz = @import("ssz");
const snappyz = @import("snappyz");
const snappyframesz = @import("snappyframesz");

const interface = @import("./interface.zig");
const node_registry = @import("./node_registry.zig");
const NodeNameRegistry = node_registry.NodeNameRegistry;

const MAX_RPC_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
const MAX_VARINT_BYTES: usize = uvarint.bufferSize(usize);
const POLL_INTERVAL_MS: u32 = 1;

const FrameDecodeError = error{
    EmptyFrame,
    PayloadTooLarge,
    Incomplete,
} || uvarint.VarintParseError;

fn encodeVarint(buffer: *std.ArrayList(u8), allocator: Allocator, value: usize) !void {
    var scratch: [MAX_VARINT_BYTES]u8 = undefined;
    const encoded = uvarint.encode(usize, value, &scratch);
    try buffer.appendSlice(allocator, encoded);
}

fn decodeVarint(bytes: []const u8) uvarint.VarintParseError!struct { value: usize, length: usize } {
    const result = try uvarint.decode(usize, bytes);
    return .{
        .value = result.value,
        .length = bytes.len - result.remaining.len,
    };
}

/// Build a request frame: varint-encoded uncompressed size + snappy-framed payload.
pub fn buildRequestFrame(allocator: Allocator, uncompressed_size: usize, snappy_payload: []const u8) ![]u8 {
    if (uncompressed_size > MAX_RPC_MESSAGE_SIZE) return error.PayloadTooLarge;
    var frame = std.ArrayList(u8).empty;
    errdefer frame.deinit(allocator);
    try encodeVarint(&frame, allocator, uncompressed_size);
    try frame.appendSlice(allocator, snappy_payload);
    return frame.toOwnedSlice(allocator);
}

/// Build a response frame: response code + varint-encoded uncompressed size + snappy-framed payload.
pub fn buildResponseFrame(allocator: Allocator, code: u8, uncompressed_size: usize, snappy_payload: []const u8) ![]u8 {
    if (uncompressed_size > MAX_RPC_MESSAGE_SIZE) return error.PayloadTooLarge;
    var frame = std.ArrayList(u8).empty;
    errdefer frame.deinit(allocator);
    try frame.append(allocator, code);
    try encodeVarint(&frame, allocator, uncompressed_size);
    try frame.appendSlice(allocator, snappy_payload);
    return frame.toOwnedSlice(allocator);
}

pub fn parseRequestFrame(bytes: []const u8) FrameDecodeError!struct {
    declared_len: usize,
    payload: []const u8,
} {
    if (bytes.len == 0) return error.EmptyFrame;
    const decoded = try decodeVarint(bytes);
    if (decoded.value > MAX_RPC_MESSAGE_SIZE) return error.PayloadTooLarge;
    return .{ .declared_len = decoded.value, .payload = bytes[decoded.length..] };
}

pub fn parseResponseFrame(bytes: []const u8) FrameDecodeError!struct {
    code: u8,
    declared_len: usize,
    payload: []const u8,
} {
    if (bytes.len == 0) return error.EmptyFrame;
    if (bytes.len == 1) return error.Incomplete;
    const decoded = try decodeVarint(bytes[1..]);
    if (decoded.value > MAX_RPC_MESSAGE_SIZE) return error.PayloadTooLarge;
    return .{
        .code = bytes[0],
        .declared_len = decoded.value,
        .payload = bytes[1 + decoded.length ..],
    };
}

pub const EthP2PNetworkParams = struct {
    networkId: u32,
    network_name: []const u8,
    /// Hex-encoded local NodeId (64 chars), derived from the discv5 identity.
    local_peer_id: []const u8,
    /// UDP port for zig-ethp2p QUIC listener (0 = OS-assigned).
    quic_listen_port: u16,
    node_registry: *const NodeNameRegistry,
    attestation_committee_count: types.SubnetId,
};

pub const EthP2PNetwork = struct {
    allocator: Allocator,
    params: EthP2PNetworkParams,

    engine: broadcast_engine.Engine,
    gossip_handler: interface.GenericGossipHandler,
    reqresp_handler: interface.ReqRespRequestHandler,
    reqresp_callbacks: std.AutoHashMapUnmanaged(u64, interface.ReqRespRequestCallback),
    next_request_id: u64,

    /// QUIC listener; null when QUIC is not compiled in.
    quic_listener: ?eth_ec_quic.EthEcQuicListener,
    poll_thread: ?Thread,
    poll_running: std.atomic.Value(bool),

    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        loop: *xev.Loop,
        params: EthP2PNetworkParams,
        logger: zeam_utils.ModuleLogger,
    ) !Self {
        var gossip_handler = try interface.GenericGossipHandler.init(
            allocator,
            loop,
            params.networkId,
            logger,
            params.node_registry,
        );
        errdefer gossip_handler.deinit();

        var reqresp_handler = try interface.ReqRespRequestHandler.init(
            allocator,
            params.networkId,
            logger,
            params.node_registry,
        );
        errdefer reqresp_handler.deinit();

        var engine = try broadcast_engine.Engine.init(allocator, params.local_peer_id, .{
            .enable_cross_session_dedup = true,
        });
        errdefer engine.deinit();

        var self = Self{
            .allocator = allocator,
            .params = params,
            .engine = engine,
            .gossip_handler = gossip_handler,
            .reqresp_handler = reqresp_handler,
            .reqresp_callbacks = .empty,
            .next_request_id = 1,
            .quic_listener = null,
            .poll_thread = null,
            .poll_running = std.atomic.Value(bool).init(false),
            .logger = logger,
            .node_registry = params.node_registry,
        };

        // Attach one RS channel per gossip topic kind.
        for (std.enums.values(interface.GossipTopicKind)) |kind| {
            switch (kind) {
                .attestation => {
                    const subnet_count: usize = if (params.attestation_committee_count > 0)
                        @intCast(params.attestation_committee_count)
                    else
                        64;
                    for (0..subnet_count) |i| {
                        const subnet_id: types.SubnetId = @intCast(i);
                        const gossip_topic = interface.GossipTopic{ .kind = .attestation, .subnet_id = subnet_id };
                        var topic_obj = try interface.LeanNetworkTopic.init(allocator, gossip_topic, .ssz_snappy, params.network_name);
                        defer topic_obj.deinit();
                        const topic_str = try topic_obj.encode();
                        defer allocator.free(topic_str);
                        _ = try self.engine.attachChannelRs(topic_str, rs_init.RsConfig.default());
                    }
                },
                else => {
                    const gossip_topic = interface.GossipTopic{ .kind = kind };
                    var topic_obj = try interface.LeanNetworkTopic.init(allocator, gossip_topic, .ssz_snappy, params.network_name);
                    defer topic_obj.deinit();
                    const topic_str = try topic_obj.encode();
                    defer allocator.free(topic_str);
                    _ = try self.engine.attachChannelRs(topic_str, rs_init.RsConfig.default());
                },
            }
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.stopPollThread();

        if (self.quic_listener) |*listener| {
            listener.deinit();
        }

        self.engine.deinit();
        self.gossip_handler.deinit();
        self.reqresp_handler.deinit();

        var it = self.reqresp_callbacks.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.reqresp_callbacks.deinit(self.allocator);
    }

    /// Bind the QUIC listener and start the poll thread.
    /// Uses port 0 for OS-assigned random port when `quic_listen_port` is 0.
    pub fn start(self: *Self) !void {
        var allocator_ref = self.allocator;
        const config = eth_ec_quic.EthEcQuicConfig{
            .tls_insecure_skip_verify = true,
        };
        const addr = eth_ec_quic.ListenAddress{
            .host = "0.0.0.0",
            .port = self.params.quic_listen_port,
        };

        self.quic_listener = try eth_ec_quic.listen(&allocator_ref, config, addr);

        self.logger.info(
            "network-{d}:: zig-ethp2p QUIC listener started on port {d}",
            .{ self.params.networkId, self.params.quic_listen_port },
        );

        self.poll_running.store(true, .release);
        self.poll_thread = try Thread.spawn(.{}, pollLoop, .{self});
    }

    fn stopPollThread(self: *Self) void {
        self.poll_running.store(false, .release);
        if (self.poll_thread) |t| {
            t.join();
            self.poll_thread = null;
        }
    }

    /// Background thread: drives the QUIC endpoint and RS engine.
    fn pollLoop(self: *Self) void {
        while (self.poll_running.load(.acquire)) {
            if (self.quic_listener) |*listener| {
                eth_ec_quic.pollListener(listener, POLL_INTERVAL_MS) catch |err| {
                    self.logger.err(
                        "network-{d}:: QUIC poll error: {any}",
                        .{ self.params.networkId, err },
                    );
                };
                // TODO(zig-ethp2p #27): accept new connections via PeerConn, complete BCAST
                // handshake, and route incoming SESS/CHUNK UNI streams to the RS engine:
                //   channel.attachRelaySession(message_id, &preamble) for SESS streams
                //   channel.relayIngestChunk(message_id, chunk_idx, chunk_bytes) for CHUNK streams
                //   when enough chunks received: channel.sessionDecode(message_id) → dispatch gossip
            } else {
                std.Thread.sleep(1_000_000); // 1 ms: no listener yet, avoid busy-loop
            }
        }
    }

    /// Called by EthP2PDiscovery when a peer is successfully dialed via discv5.
    /// The QUIC connection is already established by PeerManager at this point;
    /// we just register the peer in all RS broadcast channels.
    fn onPeerConnectedImpl(ptr: *anyopaque, peer_id: []const u8, direction: interface.PeerDirection) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);

        self.logger.info(
            "network-{d}:: peer={s}{f} connected direction={s}; adding to RS channels",
            .{ self.params.networkId, peer_id, node_name, @tagName(direction) },
        );

        // Register peer in all RS broadcast channels.
        var ch_it = self.engine.channels.iterator();
        while (ch_it.next()) |entry| {
            entry.value_ptr.*.addMember(peer_id) catch |err| {
                self.logger.err(
                    "network-{d}:: failed to add peer={s} to RS channel {s}: {any}",
                    .{ self.params.networkId, peer_id, entry.key_ptr.*, err },
                );
            };
        }
    }

    fn onPeerDisconnectedImpl(ptr: *anyopaque, peer_id: []const u8, direction: interface.PeerDirection, reason: interface.DisconnectionReason) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);
        self.logger.info(
            "network-{d}:: peer={s}{f} disconnected direction={s} reason={s}",
            .{ self.params.networkId, peer_id, node_name, @tagName(direction), @tagName(reason) },
        );

        // Remove peer from all RS channels.
        var ch_it = self.engine.channels.iterator();
        while (ch_it.next()) |entry| {
            entry.value_ptr.*.removeMember(peer_id);
        }
        // TODO(zig-ethp2p #27): close QUIC connection for this peer.
    }

    fn onPeerConnectionFailedImpl(ptr: *anyopaque, peer_id: []const u8, direction: interface.PeerDirection, result: interface.ConnectionResult) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.logger.warn(
            "network-{d}:: peer={s} connection failed direction={s} result={s}",
            .{ self.params.networkId, peer_id, @tagName(direction), @tagName(result) },
        );
    }

    /// Returns an `OnPeerEventCbHandler` that wires discovery peer events into this network.
    /// Register this with `EthP2PDiscovery.getPeerEvents().subscribe(...)` at startup.
    pub fn getPeerEventHandler(self: *Self) interface.OnPeerEventCbHandler {
        return .{
            .ptr = self,
            .onPeerConnectedCb = onPeerConnectedImpl,
            .onPeerDisconnectedCb = onPeerDisconnectedImpl,
            .onPeerConnectionFailedCb = onPeerConnectionFailedImpl,
        };
    }

    // -------------------------------------------------------------------------
    // NetworkInterface vtable implementations
    // -------------------------------------------------------------------------

    fn publish(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        var topic_obj = try data.getLeanNetworkTopic(self.allocator, self.params.network_name);
        defer topic_obj.deinit();
        const topic_str = try topic_obj.encode();
        defer self.allocator.free(topic_str);

        const payload = try data.serialize(self.allocator);
        defer self.allocator.free(payload);

        // Derive a message ID from the payload hash.
        const Sha256 = std.crypto.hash.sha2.Sha256;
        var hash: [32]u8 = undefined;
        Sha256.hash(payload, &hash, .{});
        const message_id = hash[0..20];

        const channel = self.engine.channels.get(topic_str) orelse {
            self.logger.err(
                "network-{d}:: no RS channel for topic={s}; message dropped",
                .{ self.params.networkId, topic_str },
            );
            return error.ChannelNotFound;
        };

        channel.publish(message_id, payload) catch |err| switch (err) {
            error.DuplicateMessage => {
                self.logger.debug(
                    "network-{d}:: duplicate message on topic={s}; ignoring",
                    .{ self.params.networkId, topic_str },
                );
            },
            else => return err,
        };

        self.logger.debug(
            "network-{d}:: RS-encoded gossip on topic={s} payload_len={d}",
            .{ self.params.networkId, topic_str, payload.len },
        );

        // TODO(zig-ethp2p #27): drain outbound RS chunks and send to all channel members
        // via QUIC UNI streams (SESS frame first, then one CHUNK stream per shard).
    }

    fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossip_handler.subscribe(topics, handler);
    }

    fn onGossip(ptr: *anyopaque, data: *const interface.GossipMessage, sender_peer_id: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossip_handler.onGossip(data, sender_peer_id, false);
    }

    fn sendRPCRequest(
        ptr: *anyopaque,
        peer_id: []const u8,
        req: *const interface.ReqRespRequest,
        callback: ?interface.OnReqRespResponseCbHandler,
    ) anyerror!u64 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);

        const method = std.meta.activeTag(req.*);
        const encoded = try req.serialize(self.allocator);
        defer self.allocator.free(encoded);

        const framed_payload = try snappyframesz.encode(self.allocator, encoded);
        defer self.allocator.free(framed_payload);

        const frame = try buildRequestFrame(self.allocator, encoded.len, framed_payload);
        defer self.allocator.free(frame);

        const request_id = self.next_request_id;
        self.next_request_id += 1;

        self.logger.debug(
            "network-{d}:: sendRPCRequest peer={s}{f} method={s} request_id={d} frame_len={d}",
            .{ self.params.networkId, peer_id, node_name, @tagName(method), request_id, frame.len },
        );

        if (callback) |handler| {
            const peer_id_copy = try self.allocator.dupe(u8, peer_id);
            errdefer self.allocator.free(peer_id_copy);
            var cb_entry = interface.ReqRespRequestCallback.init(method, self.allocator, handler, peer_id_copy);
            errdefer cb_entry.deinit();
            try self.reqresp_callbacks.put(self.allocator, request_id, cb_entry);
        }

        // TODO(zig-ethp2p #27): open a QUIC bidi stream to the peer and write `frame` to it,
        // then drive response reading in the poll loop.
        self.logger.warn(
            "network-{d}:: QUIC req/resp not yet wired; request_id={d} to peer={s}{f} dropped (pending zig-ethp2p #27)",
            .{ self.params.networkId, request_id, peer_id, node_name },
        );

        return request_id;
    }

    fn onRPCRequest(ptr: *anyopaque, data: *interface.ReqRespRequest, stream: interface.ReqRespServerStream) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.reqresp_handler.onReqRespRequest(data, stream);
    }

    fn subscribeReqResp(ptr: *anyopaque, handler: interface.OnReqRespRequestCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.reqresp_handler.subscribe(handler);
    }

    fn subscribePeerEvents(ptr: *anyopaque, handler: interface.OnPeerEventCbHandler) anyerror!void {
        _ = ptr;
        _ = handler;
        // EthP2PNetwork does not dispatch to external peer event handlers;
        // it registers as a listener on EthP2PDiscovery instead.
    }

    pub fn getNetworkInterface(self: *Self) interface.NetworkInterface {
        return .{
            .gossip = .{
                .ptr = self,
                .publishFn = publish,
                .subscribeFn = subscribe,
                .onGossipFn = onGossip,
            },
            .reqresp = .{
                .ptr = self,
                .sendRequestFn = sendRPCRequest,
                .onReqRespRequestFn = onRPCRequest,
                .subscribeFn = subscribeReqResp,
            },
            .peers = .{
                .ptr = self,
                .subscribeFn = subscribePeerEvents,
            },
        };
    }
};
