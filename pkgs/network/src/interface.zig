const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const xev = @import("xev");
const zeam_utils = @import("@zeam/utils");

const topic_prefix = "leanconsensus";

pub const GossipSub = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    publishFn: *const fn (ptr: *anyopaque, obj: *const GossipMessage) anyerror!void,
    subscribeFn: *const fn (ptr: *anyopaque, topics: []TopicKind, handler: OnGossipCbHandler) anyerror!void,
    onGossipFn: *const fn (ptr: *anyopaque, data: *GossipMessage) anyerror!void,

    pub fn subscribe(self: GossipSub, topics: []TopicKind, handler: OnGossipCbHandler) anyerror!void {
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

pub const NetworkInterface = struct {
    gossip: GossipSub,
    reqresp: ReqResp,
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
        for (std.enums.values(GossipEncoding)) |variant| {
            if (std.mem.eql(u8, encoded, variant.encode())) {
                return variant;
            }
        }
        return error.InvalidDecoding;
    }
};

pub const GossipTopic = struct {
    kind: TopicKind,
    encoding: GossipEncoding,
    network: []const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, kind: TopicKind, encoding: GossipEncoding, network: []const u8) !GossipTopic {
        return GossipTopic{
            .allocator = allocator,
            .kind = kind,
            .encoding = encoding,
            .network = try allocator.dupe(u8, network),
        };
    }

    pub fn encode(self: *const GossipTopic) ![:0]u8 {
        return try std.fmt.allocPrintZ(self.allocator, "/{s}/{s}/{s}/{s}", .{ topic_prefix, self.network, self.kind.encode(), self.encoding.encode() });
    }

    // topic format: /leanconsensus/<network>/<kind>/<encoding>
    pub fn decode(allocator: Allocator, topic_str: [*:0]const u8) !GossipTopic {
        const topic = std.mem.span(topic_str);
        var iter = std.mem.splitSequence(u8, topic, "/");
        _ = iter.next() orelse return error.InvalidTopic; // skip empty
        const prefix = iter.next() orelse return error.InvalidTopic;
        if (!std.mem.eql(u8, prefix, topic_prefix)) {
            return error.InvalidTopic;
        }
        const network_slice = iter.next() orelse return error.InvalidTopic;
        const kind_slice = iter.next() orelse return error.InvalidTopic;
        const encoding_slice = iter.next() orelse return error.InvalidTopic;

        const kind = try TopicKind.decode(kind_slice);
        const encoding = try GossipEncoding.decode(encoding_slice);

        return GossipTopic{
            .allocator = allocator,
            .kind = kind,
            .encoding = encoding,
            .network = try allocator.dupe(u8, network_slice),
        };
    }

    pub fn deinit(self: *GossipTopic) void {
        self.allocator.free(self.network);
    }
};

pub const TopicKind = enum {
    block,
    vote,

    pub fn encode(self: TopicKind) []const u8 {
        return std.enums.tagName(TopicKind, self).?;
    }

    pub fn decode(encoded: []const u8) !TopicKind {
        for (std.enums.values(TopicKind)) |variant| {
            if (std.mem.eql(u8, encoded, variant.encode())) {
                return variant;
            }
        }
        return error.InvalidDecoding;
    }
};

pub const GossipMessage = union(TopicKind) {
    block: types.SignedBeamBlock,
    vote: types.SignedVote,

    const Self = @This();

    pub fn getTopic(self: *const Self, allocator: Allocator, network_name: []const u8) !GossipTopic {
        const kind = std.meta.activeTag(self.*);
        return try GossipTopic.init(allocator, kind, .ssz_snappy, network_name);
    }

    pub fn getTopicKind(self: *const Self) TopicKind {
        return std.meta.activeTag(self.*);
    }

    pub fn clone(self: *const Self, allocator: Allocator) !*Self {
        const cloned_data = try allocator.create(Self);

        switch (self.*) {
            .block => {
                cloned_data.* = .{ .block = try types.sszClone(allocator, types.SignedBeamBlock, self.block) };
            },
            .vote => {
                cloned_data.* = .{ .vote = try types.sszClone(allocator, types.SignedVote, self.vote) };
            },
        }

        return cloned_data;
    }
};

pub const ReqRespMethod = enum {
    block_by_root,
};
pub const ReqRespRequest = union(ReqRespMethod) {
    block_by_root: types.BlockByRootRequest,
};

const MessagePublishWrapper = struct {
    handler: OnGossipCbHandler,
    data: *const GossipMessage,
    networkId: u32,
    logger: zeam_utils.ModuleLogger,
};

pub const GenericGossipHandler = struct {
    loop: *xev.Loop,
    timer: xev.Timer,
    allocator: Allocator,
    onGossipHandlers: std.AutoHashMapUnmanaged(TopicKind, std.ArrayListUnmanaged(OnGossipCbHandler)),
    networkId: u32,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();
    pub fn init(allocator: Allocator, loop: *xev.Loop, networkId: u32, logger: zeam_utils.ModuleLogger) !Self {
        const timer = try xev.Timer.init();
        errdefer timer.deinit();

        var onGossipHandlers: std.AutoHashMapUnmanaged(TopicKind, std.ArrayListUnmanaged(OnGossipCbHandler)) = .empty;
        errdefer {
            var it = onGossipHandlers.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit(allocator);
            }
            onGossipHandlers.deinit(allocator);
        }
        try onGossipHandlers.ensureTotalCapacity(allocator, @intCast(std.enums.values(TopicKind).len));

        for (std.enums.values(TopicKind)) |topic| {
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
        const topic_kind = data.getTopicKind();
        const handlerArr = self.onGossipHandlers.get(topic_kind).?;
        self.logger.debug("network-{d}:: ongossip handlerArr {any} for topic {any}", .{ self.networkId, handlerArr.items, topic_kind });
        for (handlerArr.items) |handler| {

            // TODO: figure out why scheduling on the loop is not working for libp2p separate net instance
            // remove this option once resolved
            if (scheduleOnLoop) {
                // TODO: track and dealloc the structures
                const c = try self.allocator.create(xev.Completion);
                c.* = undefined;

                const publishWrapper = try self.allocator.create(MessagePublishWrapper);
                const cloned_data = try data.clone(self.allocator);

                publishWrapper.* = MessagePublishWrapper{
                    .handler = handler,
                    // clone the data to be independently deallocated as the mock network publish will
                    // return the callflow back and it might dealloc the data before loop and process it
                    .data = cloned_data,
                    .networkId = self.networkId,
                    .logger = self.logger,
                };
                self.logger.debug("network-{d}:: scheduling ongossip publishWrapper={any} on loop for topic {any}", .{ self.networkId, topic_kind, publishWrapper });

                self.timer.run(
                    self.loop,
                    c,
                    1,
                    MessagePublishWrapper,
                    publishWrapper,
                    (struct {
                        fn callback(
                            ud: ?*MessagePublishWrapper,
                            _: *xev.Loop,
                            _: *xev.Completion,
                            r: xev.Timer.RunError!void,
                        ) xev.CallbackAction {
                            _ = r catch unreachable;
                            if (ud) |pwrap| {
                                pwrap.logger.debug("network-{d}:: ONGOSSIP PUBLISH callback executed", .{pwrap.networkId});
                                _ = pwrap.handler.onGossip(pwrap.data) catch void;
                            }
                            // TODO defer freeing the publishwrapper and its data but need handle to the allocator
                            // also figure out how and when to best dealloc the completion
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

    pub fn subscribe(self: *Self, topics: []TopicKind, handler: OnGossipCbHandler) anyerror!void {
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

test TopicKind {
    const kind = TopicKind.block;
    try std.testing.expect(std.mem.eql(u8, kind.encode(), "block"));
    try std.testing.expectEqual(kind, try TopicKind.decode("block"));

    const kind2 = TopicKind.vote;
    try std.testing.expect(std.mem.eql(u8, kind2.encode(), "vote"));
    try std.testing.expectEqual(kind2, try TopicKind.decode("vote"));

    try std.testing.expectError(error.InvalidDecoding, TopicKind.decode("invalid"));
}

test GossipTopic {
    const allocator = std.testing.allocator;

    var topic = try GossipTopic.init(allocator, .block, .ssz_snappy, "devnet0");
    defer topic.deinit();

    const topic_str = try topic.encode();
    defer allocator.free(topic_str);

    try std.testing.expect(std.mem.eql(u8, topic_str, "/leanconsensus/devnet0/block/ssz_snappy"));

    var decoded_topic = try GossipTopic.decode(allocator, topic_str.ptr);
    defer decoded_topic.deinit();

    try std.testing.expectEqual(topic.kind, decoded_topic.kind);
    try std.testing.expectEqual(topic.encoding, decoded_topic.encoding);
    try std.testing.expect(std.mem.eql(u8, topic.network, decoded_topic.network));
}
