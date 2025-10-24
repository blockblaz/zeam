const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const types = @import("@zeam/types");
const ssz = @import("ssz");
const xev = @import("xev");
const zeam_utils = @import("@zeam/utils");
const consensus_params = @import("@zeam/params");

const topic_prefix = "leanconsensus";
const lean_blocks_by_root_protocol = "/leanconsensus/req/lean_blocks_by_root/1/ssz_snappy";
const lean_status_protocol = "/leanconsensus/req/status/1/ssz_snappy";

pub const GossipSub = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    publishFn: *const fn (ptr: *anyopaque, obj: *const GossipMessage) anyerror!void,
    subscribeFn: *const fn (ptr: *anyopaque, topics: []GossipTopic, handler: OnGossipCbHandler) anyerror!void,
    onGossipFn: *const fn (ptr: *anyopaque, data: *GossipMessage) anyerror!void,

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

const OnGossipCbType = *const fn (*anyopaque, *const GossipMessage) anyerror!void;
pub const OnGossipCbHandler = struct {
    ptr: *anyopaque,
    onGossipCb: OnGossipCbType,
    // c: xev.Completion = undefined,

    pub fn onGossip(self: OnGossipCbHandler, data: *const GossipMessage) anyerror!void {
        return self.onGossipCb(self.ptr, data);
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
    vote,

    pub fn encode(self: GossipTopic) []const u8 {
        return std.enums.tagName(GossipTopic, self).?;
    }

    pub fn decode(encoded: []const u8) !GossipTopic {
        return std.meta.stringToEnum(GossipTopic, encoded) orelse error.InvalidDecoding;
    }
};

pub const GossipMessage = union(GossipTopic) {
    block: types.SignedBeamBlock,
    vote: types.SignedVote,

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
                try types.sszClone(allocator, types.SignedBeamBlock, self.block, &cloned_data.block);
            },
            .vote => {
                cloned_data.* = .{ .vote = undefined };
                try types.sszClone(allocator, types.SignedVote, self.vote, &cloned_data.vote);
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
            .vote => |vote| vote.toJson(allocator) catch |e| {
                std.log.err("Failed to convert vote to JSON: {any}", .{e});
                return e;
            },
        };
    }

    pub fn toJsonString(self: *const Self, allocator: Allocator) ![]const u8 {
        const message_json = try self.toJson(allocator);
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
        const message_json = try self.toJson(allocator);
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
    blocks_by_root: types.SignedBeamBlock,
    status: types.Status,

    const Self = @This();

    pub fn toJson(self: *const ReqRespResponse, allocator: Allocator) !json.Value {
        return switch (self.*) {
            .status => |status| status.toJson(allocator),
            .blocks_by_root => |block| block.toJson(allocator),
        };
    }

    pub fn toJsonString(self: *const ReqRespResponse, allocator: Allocator) ![]const u8 {
        const message_json = try self.toJson(allocator);
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

    pub fn init(method: LeanSupportedProtocol, allocator: Allocator, handler: ?OnReqRespResponseCbHandler) ReqRespRequestCallback {
        return ReqRespRequestCallback{
            .method = method,
            .allocator = allocator,
            .handler = handler,
        };
    }

    pub fn deinit(self: *ReqRespRequestCallback) void {
        _ = self;
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

    const Self = @This();

    pub fn init(allocator: Allocator, networkId: u32, logger: zeam_utils.ModuleLogger) !Self {
        return Self{
            .allocator = allocator,
            .handlers = .empty,
            .networkId = networkId,
            .logger = logger,
        };
    }

    pub fn deinit(self: *Self) void {
        self.handlers.deinit(self.allocator);
    }

    pub fn subscribe(self: *Self, handler: OnReqRespRequestCbHandler) !void {
        try self.handlers.append(self.allocator, handler);
    }

    pub fn onReqRespRequest(self: *Self, req: *const ReqRespRequest, stream: ReqRespServerStream) anyerror!void {
        self.logger.debug("network-{d}:: onReqRespRequest={any}, handlers={d}", .{ self.networkId, req, self.handlers.items.len });
        if (self.handlers.items.len == 0) {
            return error.NoHandlerSubscribed;
        }

        var handled = false;
        var last_err: ?anyerror = null;

        for (self.handlers.items) |handler| {
            handler.onReqRespRequest(req, stream) catch |err| {
                self.logger.err("network-{d}:: onReqRespRequest handler error={any}", .{ self.networkId, err });
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
    networkId: u32,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();

    fn init(allocator: Allocator, handler: OnGossipCbHandler, data: *const GossipMessage, networkId: u32, logger: zeam_utils.ModuleLogger) !*Self {
        const cloned_data = try data.clone(allocator);

        const self = try allocator.create(Self);
        self.* = MessagePublishWrapper{
            .allocator = allocator,
            .handler = handler,
            .data = cloned_data,
            .networkId = networkId,
            .logger = logger,
        };
        return self;
    }

    fn deinit(self: *Self) void {
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

    const Self = @This();

    pub fn init(allocator: Allocator, networkId: u32, logger: zeam_utils.ModuleLogger) !Self {
        return Self{
            .allocator = allocator,
            .handlers = .empty,
            .networkId = networkId,
            .logger = logger,
        };
    }

    pub fn deinit(self: *Self) void {
        self.handlers.deinit(self.allocator);
    }

    pub fn subscribe(self: *Self, handler: OnPeerEventCbHandler) !void {
        try self.handlers.append(self.allocator, handler);
    }

    pub fn onPeerConnected(self: *Self, peer_id: []const u8) anyerror!void {
        self.logger.debug("network-{d}:: PeerEventHandler.onPeerConnected peer_id={s}, handlers={d}", .{ self.networkId, peer_id, self.handlers.items.len });
        for (self.handlers.items) |handler| {
            handler.onPeerConnected(peer_id) catch |e| {
                self.logger.err("network-{d}:: onPeerConnected handler error={any}", .{ self.networkId, e });
            };
        }
    }

    pub fn onPeerDisconnected(self: *Self, peer_id: []const u8) anyerror!void {
        self.logger.debug("network-{d}:: PeerEventHandler.onPeerDisconnected peer_id={s}, handlers={d}", .{ self.networkId, peer_id, self.handlers.items.len });
        for (self.handlers.items) |handler| {
            handler.onPeerDisconnected(peer_id) catch |e| {
                self.logger.err("network-{d}:: onPeerDisconnected handler error={any}", .{ self.networkId, e });
            };
        }
    }
};

pub const GenericGossipHandler = struct {
    event_loop: *zeam_utils.EventLoop,
    timer: xev.Timer,
    allocator: Allocator,
    onGossipHandlers: std.AutoHashMapUnmanaged(GossipTopic, std.ArrayListUnmanaged(OnGossipCbHandler)),
    networkId: u32,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();
    pub fn init(allocator: Allocator, event_loop: *zeam_utils.EventLoop, networkId: u32, logger: zeam_utils.ModuleLogger) !Self {
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
            .event_loop = event_loop,
            .timer = timer,
            .onGossipHandlers = onGossipHandlers,
            .networkId = networkId,
            .logger = logger,
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

    pub fn onGossip(self: *Self, data: *const GossipMessage) anyerror!void {
        const gossip_topic = data.getGossipTopic();
        const handlerArr = self.onGossipHandlers.get(gossip_topic).?;
        self.logger.debug("network-{d}:: ongossip handlerArr {any} for topic {any}", .{ self.networkId, handlerArr.items, gossip_topic });
        for (handlerArr.items) |handler| {
            const publishWrapper = try MessagePublishWrapper.init(self.allocator, handler, data, self.networkId, self.logger);

            self.logger.debug("network-{d}:: scheduling ongossip publishWrapper={any} on loop for topic {any}", .{ self.networkId, gossip_topic, publishWrapper });

            // Create work item for thread-safe scheduling
            const work_item = zeam_utils.EventLoop.WorkItem{
                .callback = gossipWorkCallback,
                .data = publishWrapper,
            };

            // Thread-safe: notify the main event loop from any thread (including Rust thread)
            try self.event_loop.scheduleWork(work_item);
        }
        // we don't need to run the loop as this is a shared loop and is already being run by the clock
    }

    fn gossipWorkCallback(data: *anyopaque) anyerror!void {
        const pwrap: *MessagePublishWrapper = @ptrCast(@alignCast(data));
        defer pwrap.deinit();

        pwrap.logger.debug("network-{d}:: ONGOSSIP work callback executed", .{pwrap.networkId});
        try pwrap.handler.onGossip(pwrap.data);
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

    const gossip_topic2 = GossipTopic.vote;
    try std.testing.expect(std.mem.eql(u8, gossip_topic2.encode(), "vote"));
    try std.testing.expectEqual(gossip_topic2, try GossipTopic.decode("vote"));

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

test "GenericGossipHandler: multiple threads scheduling gossip concurrently" {
    const allocator = std.testing.allocator;

    var event_loop = try zeam_utils.EventLoop.init(allocator);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startHandlers();

    var logger_config = zeam_utils.getTestLoggerConfig();
    var gossip_handler = try GenericGossipHandler.init(
        allocator,
        &event_loop,
        0,
        logger_config.logger(.network),
    );
    defer gossip_handler.deinit();

    var received_count: usize = 0;
    var mutex = std.Thread.Mutex{};

    const TestHandler = struct {
        count: *usize,
        mutex: *std.Thread.Mutex,

        pub fn onGossip(ptr: *anyopaque, msg: *const GossipMessage) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.mutex.lock();
            defer self.mutex.unlock();
            self.count.* += 1;
            _ = msg.getGossipTopic();
        }
    };

    var test_handler = TestHandler{
        .count = &received_count,
        .mutex = &mutex,
    };

    const handler_cb = OnGossipCbHandler{
        .ptr = &test_handler,
        .onGossipFn = TestHandler.onGossip,
    };

    const topics = [_]GossipTopic{.lean_block};
    try gossip_handler.subscribe(&topics, handler_cb);

    // Create test messages
    var test_blocks: [10]types.BeamBlock = undefined;
    var gossip_msgs: [10]GossipMessage = undefined;

    for (0..10) |i| {
        test_blocks[i] = types.BeamBlock{
            .message = .{
                .slot = @intCast(i + 1),
                .proposer_index = 0,
                .parent_root = [_]u8{0} ** 32,
                .state_root = [_]u8{0} ** 32,
                .body_root = [_]u8{0} ** 32,
            },
            .signature = [_]u8{0} ** 96,
        };
        gossip_msgs[i] = GossipMessage{
            .lean_block = test_blocks[i],
        };
    }

    const WorkerThread = struct {
        fn run(
            gh: *GenericGossipHandler,
            msgs: []const GossipMessage,
            start: usize,
            count: usize,
        ) void {
            for (start..start + count) |i| {
                gh.onGossip(&msgs[i]) catch unreachable;
            }
        }
    };

    const num_threads = 4;
    const msgs_per_thread = 2;
    var threads: [num_threads]std.Thread = undefined;

    // Spawn multiple worker threads
    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(
            .{},
            WorkerThread.run,
            .{
                &gossip_handler,
                gossip_msgs[0..],
                i * msgs_per_thread,
                msgs_per_thread,
            },
        );
    }

    // Wait for all threads to finish
    for (threads) |thread| {
        thread.join();
    }

    // Run the loop multiple times to process all scheduled work
    var max_iterations: usize = 100;
    const expected_count = num_threads * msgs_per_thread;

    while (max_iterations > 0) : (max_iterations -= 1) {
        try event_loop.run(.no_wait);

        mutex.lock();
        const current_count = received_count;
        mutex.unlock();

        if (current_count == expected_count) {
            break;
        }

        std.time.sleep(1 * std.time.ns_per_ms);
    }

    // Verify all messages were processed
    try std.testing.expectEqual(expected_count, received_count);
}
