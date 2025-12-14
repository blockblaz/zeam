const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const types = @import("@zeam/types");
const ssz = @import("ssz");
const xev = @import("xev");
const zeam_utils = @import("@zeam/utils");
const consensus_params = @import("@zeam/params");

const node_registry = @import("./node_registry.zig");
const NodeNameRegistry = node_registry.NodeNameRegistry;

const topic_prefix = "leanconsensus";
const lean_blocks_by_root_protocol = "/leanconsensus/req/lean_blocks_by_root/1/ssz_snappy";
const lean_status_protocol = "/leanconsensus/req/status/1/ssz_snappy";

fn freeJsonValue(val: *json.Value, allocator: Allocator) void {
    switch (val.*) {
        .object => |*o| {
            var it = o.iterator();
            while (it.next()) |entry| {
                freeJsonValue(&entry.value_ptr.*, allocator);
            }
            o.deinit();
        },
        .array => |*a| {
            for (a.items) |*item| {
                freeJsonValue(item, allocator);
            }
            a.deinit();
        },
        .string => |s| allocator.free(s),
        else => {},
    }
}

pub const GossipSub = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    publishFn: *const fn (ptr: *anyopaque, obj: *const GossipMessage) anyerror!void,
    subscribeFn: *const fn (ptr: *anyopaque, topics: []GossipTopic, handler: OnGossipCbHandler) anyerror!void,
    onGossipFn: *const fn (ptr: *anyopaque, data: *GossipMessage, sender_peer_id: []const u8) anyerror!void,

    pub fn subscribe(self: GossipSub, topics: []GossipTopic, handler: OnGossipCbHandler) anyerror!void {
        return self.subscribeFn(self.ptr, topics, handler);
    }

    pub fn publish(self: GossipSub, obj: *const GossipMessage) anyerror!void {
        return self.publishFn(self.ptr, obj);
    }
};

pub const ReqResp = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    sendRequestFn: *const fn (ptr: *anyopaque, peer_id: []const u8, req: *const ReqRespRequest, callback: ?OnReqRespResponseCbHandler) anyerror!u64,
    onReqRespRequestFn: *const fn (ptr: *anyopaque, data: *ReqRespRequest, stream: ReqRespServerStream) anyerror!void,
    subscribeFn: *const fn (ptr: *anyopaque, handler: OnReqRespRequestCbHandler) anyerror!void,

    pub fn subscribe(self: ReqResp, handler: OnReqRespRequestCbHandler) anyerror!void {
        return self.subscribeFn(self.ptr, handler);
    }

    pub fn sendRequest(self: ReqResp, peer_id: []const u8, req: *const ReqRespRequest, callback: ?OnReqRespResponseCbHandler) anyerror!u64 {
        return self.sendRequestFn(self.ptr, peer_id, req, callback);
    }
};

pub const PeerEvents = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    subscribeFn: *const fn (ptr: *anyopaque, handler: OnPeerEventCbHandler) anyerror!void,

    pub fn subscribe(self: PeerEvents, handler: OnPeerEventCbHandler) anyerror!void {
        return self.subscribeFn(self.ptr, handler);
    }
};

pub const NetworkInterface = struct {
    gossip: GossipSub,
    reqresp: ReqResp,
    peers: PeerEvents,
};

const OnGossipCbType = *const fn (*anyopaque, *const GossipMessage, sender_peer_id: []const u8) anyerror!void;
pub const OnGossipCbHandler = struct {
    ptr: *anyopaque,
    onGossipCb: OnGossipCbType,
    // c: xev.Completion = undefined,

    pub fn onGossip(self: OnGossipCbHandler, data: *const GossipMessage, sender_peer_id: []const u8) anyerror!void {
        return self.onGossipCb(self.ptr, data, sender_peer_id);
    }
};

pub const GossipEncoding = enum {
    ssz_snappy,

    pub fn encode(self: GossipEncoding) []const u8 {
        return std.enums.tagName(GossipEncoding, self).?;
    }

    pub fn decode(encoded: []const u8) !GossipEncoding {
        return std.meta.stringToEnum(GossipEncoding, encoded) orelse error.InvalidDecoding;
    }
};

pub const LeanNetworkTopic = struct {
    gossip_topic: GossipTopic,
    encoding: GossipEncoding,
    network: []const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, gossip_topic: GossipTopic, encoding: GossipEncoding, network: []const u8) !LeanNetworkTopic {
        return LeanNetworkTopic{
            .allocator = allocator,
            .gossip_topic = gossip_topic,
            .encoding = encoding,
            .network = try allocator.dupe(u8, network),
        };
    }

    pub fn encodeZ(self: *const LeanNetworkTopic) ![:0]u8 {
        return try std.fmt.allocPrintZ(self.allocator, "/{s}/{s}/{s}/{s}", .{ topic_prefix, self.network, self.gossip_topic.encode(), self.encoding.encode() });
    }

    pub fn encode(self: *const LeanNetworkTopic) ![]u8 {
        return try std.fmt.allocPrint(self.allocator, "/{s}/{s}/{s}/{s}", .{ topic_prefix, self.network, self.gossip_topic.encode(), self.encoding.encode() });
    }

    // topic format: /leanconsensus/<network>/<name>/<encoding>
    pub fn decode(allocator: Allocator, topic_str: [*:0]const u8) !LeanNetworkTopic {
        const topic = std.mem.span(topic_str);
        var iter = std.mem.splitSequence(u8, topic, "/");
        _ = iter.next() orelse return error.InvalidTopic; // skip empty
        const prefix = iter.next() orelse return error.InvalidTopic;
        if (!std.mem.eql(u8, prefix, topic_prefix)) {
            return error.InvalidTopic;
        }
        const network_slice = iter.next() orelse return error.InvalidTopic;
        const gossip_topic_slice = iter.next() orelse return error.InvalidTopic;
        const encoding_slice = iter.next() orelse return error.InvalidTopic;

        const gossip_topic = try GossipTopic.decode(gossip_topic_slice);
        const encoding = try GossipEncoding.decode(encoding_slice);

        return LeanNetworkTopic{
            .allocator = allocator,
            .gossip_topic = gossip_topic,
            .encoding = encoding,
            .network = try allocator.dupe(u8, network_slice),
        };
    }

    pub fn deinit(self: *LeanNetworkTopic) void {
        self.allocator.free(self.network);
    }
};

pub const GossipTopic = enum {
    block,
    attestation,

    pub fn encode(self: GossipTopic) []const u8 {
        return std.enums.tagName(GossipTopic, self).?;
    }

    pub fn decode(encoded: []const u8) !GossipTopic {
        return std.meta.stringToEnum(GossipTopic, encoded) orelse error.InvalidDecoding;
    }
};

pub const GossipMessage = union(GossipTopic) {
    block: types.SignedBlockWithAttestation,
    attestation: types.SignedAttestation,

    const Self = @This();

    pub fn getLeanNetworkTopic(self: *const Self, allocator: Allocator, network_name: []const u8) !LeanNetworkTopic {
        const gossip_topic = std.meta.activeTag(self.*);
        return try LeanNetworkTopic.init(allocator, gossip_topic, .ssz_snappy, network_name);
    }

    pub fn getGossipTopic(self: *const Self) GossipTopic {
        return std.meta.activeTag(self.*);
    }

    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        var serialized = std.ArrayList(u8).init(allocator);
        errdefer serialized.deinit();

        switch (self.*) {
            inline else => |payload, tag| {
                const PayloadType = std.meta.TagPayload(Self, tag);
                try ssz.serialize(PayloadType, payload, &serialized);
            },
        }

        return serialized.toOwnedSlice();
    }

    pub fn clone(self: *const Self, allocator: Allocator) !*Self {
        const cloned_data = try allocator.create(Self);

        switch (self.*) {
            .block => {
                cloned_data.* = .{ .block = undefined };
                try types.sszClone(allocator, types.SignedBlockWithAttestation, self.block, &cloned_data.block);
            },
            .attestation => {
                cloned_data.* = .{ .attestation = undefined };
                try types.sszClone(allocator, types.SignedAttestation, self.attestation, &cloned_data.attestation);
            },
        }

        return cloned_data;
    }

    pub fn toJson(self: *const Self, allocator: Allocator) !json.Value {
        return switch (self.*) {
            .block => |block| block.toJson(allocator) catch |e| {
                std.log.err("Failed to convert block to JSON: {any}", .{e});
                return e;
            },
            .attestation => |attestation| attestation.toJson(allocator) catch |e| {
                std.log.err("Failed to convert attestation to JSON: {any}", .{e});
                return e;
            },
        };
    }

    pub fn toJsonString(self: *const Self, allocator: Allocator) ![]const u8 {
        var message_json = try self.toJson(allocator);
        defer freeJsonValue(&message_json, allocator);
        return zeam_utils.jsonToString(allocator, message_json);
    }
};

pub const LeanSupportedProtocol = enum {
    blocks_by_root,
    status,

    pub fn protocolId(self: LeanSupportedProtocol) []const u8 {
        return switch (self) {
            .blocks_by_root => lean_blocks_by_root_protocol,
            .status => lean_status_protocol,
        };
    }

    pub fn name(self: LeanSupportedProtocol) []const u8 {
        return @tagName(self);
    }

    pub fn fromSlice(slice: []const u8) ?LeanSupportedProtocol {
        const protocols = comptime std.enums.values(LeanSupportedProtocol);
        inline for (protocols) |value| {
            if (std.mem.eql(u8, slice, value.protocolId())) return value;
        }
        return null;
    }

    pub fn fromProtocolId(protocol_id: []const u8) !LeanSupportedProtocol {
        if (std.mem.eql(u8, protocol_id, lean_status_protocol)) {
            return .status;
        }

        if (std.mem.eql(u8, protocol_id, lean_blocks_by_root_protocol)) {
            return .blocks_by_root;
        }

        return error.UnsupportedProtocol;
    }
};

pub const ReqRespRequest = union(LeanSupportedProtocol) {
    blocks_by_root: types.BlockByRootRequest,
    status: types.Status,

    const Self = @This();

    pub fn toJson(self: *const ReqRespRequest, allocator: Allocator) !json.Value {
        return switch (self.*) {
            .status => |status| status.toJson(allocator),
            .blocks_by_root => |request| request.toJson(allocator),
        };
    }

    pub fn toJsonString(self: *const ReqRespRequest, allocator: Allocator) ![]const u8 {
        var message_json = try self.toJson(allocator);
        defer freeJsonValue(&message_json, allocator);
        return zeam_utils.jsonToString(allocator, message_json);
    }

    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        var serialized = std.ArrayList(u8).init(allocator);
        errdefer serialized.deinit();

        switch (self.*) {
            inline else => |payload, tag| {
                const PayloadType = std.meta.TagPayload(Self, tag);
                try ssz.serialize(PayloadType, payload, &serialized);
            },
        }

        return serialized.toOwnedSlice();
    }

    fn initPayload(comptime tag: LeanSupportedProtocol, allocator: Allocator) !std.meta.TagPayload(Self, tag) {
        const PayloadType = std.meta.TagPayload(Self, tag);
        return switch (tag) {
            .blocks_by_root => PayloadType{
                .roots = try ssz.utils.List(types.Root, consensus_params.MAX_REQUEST_BLOCKS).init(allocator),
            },
            inline else => @as(PayloadType, undefined),
        };
    }

    fn deinitPayload(comptime tag: LeanSupportedProtocol, payload: *std.meta.TagPayload(Self, tag)) void {
        switch (tag) {
            .blocks_by_root => payload.roots.deinit(),
            inline else => {},
        }
    }

    pub fn deserialize(allocator: Allocator, method: LeanSupportedProtocol, bytes: []const u8) !Self {
        return switch (method) {
            inline else => |tag| {
                const PayloadType = std.meta.TagPayload(Self, tag);
                var payload = try initPayload(tag, allocator);
                var succeeded = false;
                defer if (!succeeded) deinitPayload(tag, &payload);
                try ssz.deserialize(PayloadType, bytes, &payload, allocator);
                succeeded = true;
                return @unionInit(Self, @tagName(tag), payload);
            },
        };
    }

    pub fn deinit(self: *ReqRespRequest) void {
        switch (self.*) {
            inline else => |*payload, tag| deinitPayload(tag, payload),
        }
    }
};
pub const ReqRespResponse = union(LeanSupportedProtocol) {
    blocks_by_root: types.SignedBlockWithAttestation,
    status: types.Status,

    const Self = @This();

    pub fn toJson(self: *const ReqRespResponse, allocator: Allocator) !json.Value {
        return switch (self.*) {
            .status => |status| status.toJson(allocator),
            .blocks_by_root => |block| block.toJson(allocator),
        };
    }

    pub fn toJsonString(self: *const ReqRespResponse, allocator: Allocator) ![]const u8 {
        var message_json = try self.toJson(allocator);
        defer freeJsonValue(&message_json, allocator);
        return zeam_utils.jsonToString(allocator, message_json);
    }

    pub fn serialize(self: *const ReqRespResponse, allocator: Allocator) ![]u8 {
        var serialized = std.ArrayList(u8).init(allocator);
        errdefer serialized.deinit();

        switch (self.*) {
            inline else => |payload, tag| {
                const PayloadType = std.meta.TagPayload(Self, tag);
                try ssz.serialize(PayloadType, payload, &serialized);
            },
        }

        return serialized.toOwnedSlice();
    }

    pub fn deserialize(allocator: Allocator, method: LeanSupportedProtocol, bytes: []const u8) !ReqRespResponse {
        return switch (method) {
            inline else => |tag| {
                const PayloadType = std.meta.TagPayload(Self, tag);
                var payload: PayloadType = undefined;
                try ssz.deserialize(PayloadType, bytes, &payload, allocator);
                return @unionInit(Self, @tagName(tag), payload);
            },
        };
    }

    pub fn deinit(self: *ReqRespResponse) void {
        switch (self.*) {
            .status => {},
            .blocks_by_root => |*block| block.deinit(),
        }
    }
};

pub const ReqRespServerStream = struct {
    ptr: *anyopaque,
    sendResponseFn: *const fn (ptr: *anyopaque, response: *const ReqRespResponse) anyerror!void,
    sendErrorFn: *const fn (ptr: *anyopaque, code: u32, message: []const u8) anyerror!void,
    finishFn: *const fn (ptr: *anyopaque) anyerror!void,
    isFinishedFn: *const fn (ptr: *anyopaque) bool,
    getPeerIdFn: ?*const fn (ptr: *anyopaque) ?[]const u8 = null,

    const Self = @This();

    pub const Error = error{ServerStreamUnsupported};

    pub fn sendResponse(self: Self, response: *const ReqRespResponse) anyerror!void {
        return self.sendResponseFn(self.ptr, response);
    }

    pub fn sendError(self: Self, code: u32, message: []const u8) anyerror!void {
        return self.sendErrorFn(self.ptr, code, message);
    }

    pub fn finish(self: Self) anyerror!void {
        return self.finishFn(self.ptr);
    }

    pub fn isFinished(self: Self) bool {
        return self.isFinishedFn(self.ptr);
    }

    pub fn getPeerId(self: Self) ?[]const u8 {
        if (self.getPeerIdFn) |fn_ptr| {
            return fn_ptr(self.ptr);
        }
        return null;
    }
};
pub const ReqRespResponseError = struct {
    code: u32,
    message: []const u8,

    pub fn deinit(self: *ReqRespResponseError, allocator: Allocator) void {
        allocator.free(self.message);
    }
};

pub const ReqRespResponseEvent = struct {
    method: LeanSupportedProtocol,
    request_id: u64,
    payload: Payload,

    const Payload = union(enum) {
        success: ReqRespResponse,
        failure: ReqRespResponseError,
        completed,
    };

    pub fn initSuccess(request_id: u64, method: LeanSupportedProtocol, response: ReqRespResponse) ReqRespResponseEvent {
        return ReqRespResponseEvent{
            .method = method,
            .request_id = request_id,
            .payload = .{ .success = response },
        };
    }

    pub fn initError(request_id: u64, method: LeanSupportedProtocol, err: ReqRespResponseError) ReqRespResponseEvent {
        return ReqRespResponseEvent{
            .method = method,
            .request_id = request_id,
            .payload = .{ .failure = err },
        };
    }

    pub fn initCompleted(request_id: u64, method: LeanSupportedProtocol) ReqRespResponseEvent {
        return ReqRespResponseEvent{
            .method = method,
            .request_id = request_id,
            .payload = .completed,
        };
    }

    pub fn deinit(self: *ReqRespResponseEvent, allocator: Allocator) void {
        switch (self.payload) {
            .success => |*resp| resp.deinit(),
            .failure => |*err| err.deinit(allocator),
            .completed => {},
        }
    }
};

pub const ReqRespRequestCallback = struct {
    method: LeanSupportedProtocol,
    allocator: Allocator,
    handler: ?OnReqRespResponseCbHandler,
    peer_id: []const u8,

    pub fn init(method: LeanSupportedProtocol, allocator: Allocator, handler: ?OnReqRespResponseCbHandler, peer_id: []const u8) ReqRespRequestCallback {
        return ReqRespRequestCallback{
            .method = method,
            .allocator = allocator,
            .handler = handler,
            .peer_id = peer_id,
        };
    }

    pub fn deinit(self: *ReqRespRequestCallback) void {
        // peer_id is owned by the callback, free it
        self.allocator.free(self.peer_id);
    }

    pub fn notify(self: *ReqRespRequestCallback, event: *const ReqRespResponseEvent) anyerror!void {
        if (self.handler) |handler| {
            try handler.onReqRespResponse(event);
        }
    }
};

const OnReqRespResponseCbType = *const fn (*anyopaque, *const ReqRespResponseEvent) anyerror!void;
pub const OnReqRespResponseCbHandler = struct {
    ptr: *anyopaque,
    onReqRespResponseCb: OnReqRespResponseCbType,

    pub fn onReqRespResponse(self: OnReqRespResponseCbHandler, data: *const ReqRespResponseEvent) anyerror!void {
        return self.onReqRespResponseCb(self.ptr, data);
    }
};

const OnReqRespRequestCbType = *const fn (*anyopaque, *const ReqRespRequest, ReqRespServerStream) anyerror!void;
pub const OnReqRespRequestCbHandler = struct {
    ptr: *anyopaque,
    onReqRespRequestCb: OnReqRespRequestCbType,
    // c: xev.Completion = undefined,

    pub fn onReqRespRequest(self: OnReqRespRequestCbHandler, data: *const ReqRespRequest, stream: ReqRespServerStream) anyerror!void {
        return self.onReqRespRequestCb(self.ptr, data, stream);
    }
};
pub const ReqRespRequestHandler = struct {
    allocator: Allocator,
    handlers: std.ArrayListUnmanaged(OnReqRespRequestCbHandler),
    networkId: u32,
    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,

    const Self = @This();

    pub fn init(allocator: Allocator, networkId: u32, logger: zeam_utils.ModuleLogger, registry: *const NodeNameRegistry) !Self {
        return Self{
            .allocator = allocator,
            .handlers = .empty,
            .networkId = networkId,
            .logger = logger,
            .node_registry = registry,
        };
    }

    pub fn deinit(self: *Self) void {
        self.handlers.deinit(self.allocator);
    }

    pub fn subscribe(self: *Self, handler: OnReqRespRequestCbHandler) !void {
        try self.handlers.append(self.allocator, handler);
    }

    pub fn onReqRespRequest(self: *Self, req: *const ReqRespRequest, stream: ReqRespServerStream) anyerror!void {
        const peer_id_opt = stream.getPeerId();
        const peer_id = peer_id_opt orelse "unknown";
        const node_name = if (peer_id_opt) |pid| self.node_registry.getNodeNameFromPeerId(pid) else zeam_utils.OptionalNode.init(null);
        self.logger.debug("network-{d}:: onReqRespRequest={any}, handlers={d} from peer={s}{}", .{ self.networkId, req, self.handlers.items.len, peer_id, node_name });
        if (self.handlers.items.len == 0) {
            return error.NoHandlerSubscribed;
        }

        var handled = false;
        var last_err: ?anyerror = null;

        for (self.handlers.items) |handler| {
            handler.onReqRespRequest(req, stream) catch |err| {
                self.logger.err("network-{d}:: onReqRespRequest handler error={any} from peer={s}{}", .{ self.networkId, err, peer_id, node_name });
                last_err = err;
                continue;
            };

            handled = true;

            if (stream.isFinished()) {
                break;
            }
        }

        if (!handled) {
            return last_err orelse error.NoHandlerSubscribed;
        }
    }
};

const MessagePublishWrapper = struct {
    allocator: Allocator,
    handler: OnGossipCbHandler,
    data: *const GossipMessage,
    sender_peer_id: []const u8,
    networkId: u32,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();

    fn init(allocator: Allocator, handler: OnGossipCbHandler, data: *const GossipMessage, sender_peer_id: []const u8, networkId: u32, logger: zeam_utils.ModuleLogger) !*Self {
        const cloned_data = try data.clone(allocator);
        const sender_peer_id_copy = try allocator.dupe(u8, sender_peer_id);

        const self = try allocator.create(Self);
        self.* = MessagePublishWrapper{
            .allocator = allocator,
            .handler = handler,
            .data = cloned_data,
            .sender_peer_id = sender_peer_id_copy,
            .networkId = networkId,
            .logger = logger,
        };
        return self;
    }

    fn deinit(self: *Self) void {
        self.allocator.free(self.sender_peer_id);
        self.allocator.destroy(self.data);
        self.allocator.destroy(self);
    }
};

pub const OnPeerEventCbType = *const fn (*anyopaque, peer_id: []const u8) anyerror!void;
pub const OnPeerEventCbHandler = struct {
    ptr: *anyopaque,
    onPeerConnectedCb: OnPeerEventCbType,
    onPeerDisconnectedCb: OnPeerEventCbType,

    pub fn onPeerConnected(self: OnPeerEventCbHandler, peer_id: []const u8) anyerror!void {
        return self.onPeerConnectedCb(self.ptr, peer_id);
    }

    pub fn onPeerDisconnected(self: OnPeerEventCbHandler, peer_id: []const u8) anyerror!void {
        return self.onPeerDisconnectedCb(self.ptr, peer_id);
    }
};

pub const PeerEventHandler = struct {
    allocator: Allocator,
    handlers: std.ArrayListUnmanaged(OnPeerEventCbHandler),
    networkId: u32,
    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,

    const Self = @This();

    pub fn init(allocator: Allocator, networkId: u32, logger: zeam_utils.ModuleLogger, registry: *const NodeNameRegistry) !Self {
        return Self{
            .allocator = allocator,
            .handlers = .empty,
            .networkId = networkId,
            .logger = logger,
            .node_registry = registry,
        };
    }

    pub fn deinit(self: *Self) void {
        self.handlers.deinit(self.allocator);
    }

    pub fn subscribe(self: *Self, handler: OnPeerEventCbHandler) !void {
        try self.handlers.append(self.allocator, handler);
    }

    pub fn onPeerConnected(self: *Self, peer_id: []const u8) anyerror!void {
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);
        self.logger.debug("network-{d}:: PeerEventHandler.onPeerConnected peer_id={s}{}, handlers={d}", .{ self.networkId, peer_id, node_name, self.handlers.items.len });
        for (self.handlers.items) |handler| {
            handler.onPeerConnected(peer_id) catch |e| {
                self.logger.err("network-{d}:: onPeerConnected handler error={any}", .{ self.networkId, e });
            };
        }
    }

    pub fn onPeerDisconnected(self: *Self, peer_id: []const u8) anyerror!void {
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);
        self.logger.debug("network-{d}:: PeerEventHandler.onPeerDisconnected peer_id={s}{}, handlers={d}", .{ self.networkId, peer_id, node_name, self.handlers.items.len });
        for (self.handlers.items) |handler| {
            handler.onPeerDisconnected(peer_id) catch |e| {
                self.logger.err("network-{d}:: onPeerDisconnected handler error={any}", .{ self.networkId, e });
            };
        }
    }
};

pub const GenericGossipHandler = struct {
    loop: *xev.Loop,
    timer: xev.Timer,
    allocator: Allocator,
    onGossipHandlers: std.AutoHashMapUnmanaged(GossipTopic, std.ArrayListUnmanaged(OnGossipCbHandler)),
    networkId: u32,
    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,

    const Self = @This();
    pub fn init(allocator: Allocator, loop: *xev.Loop, networkId: u32, logger: zeam_utils.ModuleLogger, registry: *const NodeNameRegistry) !Self {
        const timer = try xev.Timer.init();
        errdefer timer.deinit();

        var onGossipHandlers: std.AutoHashMapUnmanaged(GossipTopic, std.ArrayListUnmanaged(OnGossipCbHandler)) = .empty;
        errdefer {
            var it = onGossipHandlers.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit(allocator);
            }
            onGossipHandlers.deinit(allocator);
        }
        try onGossipHandlers.ensureTotalCapacity(allocator, @intCast(std.enums.values(GossipTopic).len));

        for (std.enums.values(GossipTopic)) |topic| {
            var arr: std.ArrayListUnmanaged(OnGossipCbHandler) = .empty;
            errdefer arr.deinit(allocator);
            try onGossipHandlers.put(allocator, topic, arr);
        }

        return Self{
            .allocator = allocator,
            .loop = loop,
            .timer = timer,
            .onGossipHandlers = onGossipHandlers,
            .networkId = networkId,
            .logger = logger,
            .node_registry = registry,
        };
    }

    pub fn deinit(self: *Self) void {
        self.timer.deinit();
        var it = self.onGossipHandlers.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.onGossipHandlers.deinit(self.allocator);
    }

    pub fn onGossip(self: *Self, data: *const GossipMessage, sender_peer_id: []const u8, scheduleOnLoop: bool) anyerror!void {
        const gossip_topic = data.getGossipTopic();
        const handlerArr = self.onGossipHandlers.get(gossip_topic).?;
        const node_name = self.node_registry.getNodeNameFromPeerId(sender_peer_id);
        self.logger.debug("network-{d}:: ongossip handlerArr {any} for topic {any} from peer={s}{}", .{ self.networkId, handlerArr.items, gossip_topic, sender_peer_id, node_name });
        for (handlerArr.items) |handler| {

            // TODO: figure out why scheduling on the loop is not working for libp2p separate net instance
            // remove this option once resolved
            if (scheduleOnLoop) {
                const publishWrapper = try MessagePublishWrapper.init(self.allocator, handler, data, sender_peer_id, self.networkId, self.logger);

                self.logger.debug("network-{d}:: scheduling ongossip publishWrapper={any} on loop for topic {any}", .{ self.networkId, gossip_topic, publishWrapper });

                // Create a separate completion object for each handler to avoid conflicts
                const completion = try self.allocator.create(xev.Completion);
                completion.* = undefined;

                self.timer.run(
                    self.loop,
                    completion,
                    1,
                    MessagePublishWrapper,
                    publishWrapper,
                    (struct {
                        fn callback(
                            ud: ?*MessagePublishWrapper,
                            _: *xev.Loop,
                            c: *xev.Completion,
                            r: xev.Timer.RunError!void,
                        ) xev.CallbackAction {
                            _ = r catch unreachable;
                            if (ud) |pwrap| {
                                pwrap.logger.debug("network-{d}:: ONGOSSIP PUBLISH callback executed", .{pwrap.networkId});
                                _ = pwrap.handler.onGossip(pwrap.data, pwrap.sender_peer_id) catch void;
                                defer pwrap.deinit();
                                // Clean up the completion object
                                pwrap.allocator.destroy(c);
                            }
                            return .disarm;
                        }
                    }).callback,
                );
            } else {
                handler.onGossip(data, sender_peer_id) catch |e| {
                    self.logger.err("network-{d}:: onGossip handler error={any}", .{ self.networkId, e });
                };
            }
        }
        // we don't need to run the loop as this is a shared loop and is already being run by the clock
    }

    pub fn subscribe(self: *Self, topics: []GossipTopic, handler: OnGossipCbHandler) anyerror!void {
        for (topics) |topic| {
            // handlerarr should already be there
            var handlerArr = self.onGossipHandlers.get(topic).?;
            try handlerArr.append(self.allocator, handler);
            try self.onGossipHandlers.put(self.allocator, topic, handlerArr);
        }
    }
};

test GossipEncoding {
    const enc = GossipEncoding.ssz_snappy;
    try std.testing.expect(std.mem.eql(u8, enc.encode(), "ssz_snappy"));
    try std.testing.expectEqual(enc, try GossipEncoding.decode("ssz_snappy"));

    try std.testing.expectError(error.InvalidDecoding, GossipEncoding.decode("invalid"));
}

test GossipTopic {
    const gossip_topic = GossipTopic.block;
    try std.testing.expect(std.mem.eql(u8, gossip_topic.encode(), "block"));
    try std.testing.expectEqual(gossip_topic, try GossipTopic.decode("block"));

    const gossip_topic2 = GossipTopic.attestation;
    try std.testing.expect(std.mem.eql(u8, gossip_topic2.encode(), "attestation"));
    try std.testing.expectEqual(gossip_topic2, try GossipTopic.decode("attestation"));

    try std.testing.expectError(error.InvalidDecoding, GossipTopic.decode("invalid"));
}

test LeanNetworkTopic {
    const allocator = std.testing.allocator;

    var topic = try LeanNetworkTopic.init(allocator, .block, .ssz_snappy, "devnet0");
    defer topic.deinit();

    const topic_str = try topic.encodeZ();
    defer allocator.free(topic_str);

    try std.testing.expect(std.mem.eql(u8, topic_str, "/leanconsensus/devnet0/block/ssz_snappy"));

    var decoded_topic = try LeanNetworkTopic.decode(allocator, topic_str.ptr);
    defer decoded_topic.deinit();

    try std.testing.expectEqual(topic.gossip_topic, decoded_topic.gossip_topic);
    try std.testing.expectEqual(topic.encoding, decoded_topic.encoding);
    try std.testing.expect(std.mem.eql(u8, topic.network, decoded_topic.network));
}
