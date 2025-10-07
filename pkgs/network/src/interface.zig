const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const types = @import("@zeam/types");
const xev = @import("xev");
const zeam_utils = @import("@zeam/utils");

const topic_prefix = "leanconsensus";

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
    reqRespFn: *const fn (ptr: *anyopaque, obj: *ReqRespRequest) anyerror!void,
    onReqFn: *const fn (ptr: *anyopaque, data: *ReqRespRequest) anyerror!void,
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

pub const ReqRespMethod = enum {
    block_by_root,
};
pub const ReqRespRequest = union(ReqRespMethod) {
    block_by_root: types.BlockByRootRequest,
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
    loop: *xev.Loop,
    timer: xev.Timer,
    allocator: Allocator,
    onGossipHandlers: std.AutoHashMapUnmanaged(GossipTopic, std.ArrayListUnmanaged(OnGossipCbHandler)),
    networkId: u32,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();
    pub fn init(allocator: Allocator, loop: *xev.Loop, networkId: u32, logger: zeam_utils.ModuleLogger) !Self {
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

    pub fn onGossip(self: *Self, data: *const GossipMessage, scheduleOnLoop: bool) anyerror!void {
        const gossip_topic = data.getGossipTopic();
        const handlerArr = self.onGossipHandlers.get(gossip_topic).?;
        self.logger.debug("network-{d}:: ongossip handlerArr {any} for topic {any}", .{ self.networkId, handlerArr.items, gossip_topic });
        for (handlerArr.items) |handler| {

            // TODO: figure out why scheduling on the loop is not working for libp2p separate net instance
            // remove this option once resolved
            if (scheduleOnLoop) {
                const publishWrapper = try MessagePublishWrapper.init(self.allocator, handler, data, self.networkId, self.logger);

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
                                _ = pwrap.handler.onGossip(pwrap.data) catch void;
                                defer pwrap.deinit();
                                // Clean up the completion object
                                pwrap.allocator.destroy(c);
                            }
                            return .disarm;
                        }
                    }).callback,
                );
            } else {
                handler.onGossip(data) catch |e| {
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
