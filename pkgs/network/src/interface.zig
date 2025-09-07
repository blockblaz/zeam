const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const xev = @import("xev");

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

pub const GossipTopic = enum {
    block,
    vote,
};
pub const GossipMessage = union(GossipTopic) {
    block: types.SignedBeamBlock,
    vote: types.SignedVote,

    const Self = @This();
    // figureout is there a generic way to find active enum
    pub fn getTopic(self: *const Self) GossipTopic {
        return std.meta.activeTag(self.*);
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
};

pub const GenericGossipHandler = struct {
    loop: *xev.Loop,
    timer: xev.Timer,
    allocator: Allocator,
    onGossipHandlers: std.AutoHashMap(GossipTopic, std.ArrayList(OnGossipCbHandler)),
    networkId: u32,

    const Self = @This();
    pub fn init(allocator: Allocator, loop: *xev.Loop, networkId: u32) !Self {
        const timer = try xev.Timer.init();

        var onGossipHandlers = std.AutoHashMap(GossipTopic, std.ArrayList(OnGossipCbHandler)).init(allocator);
        for (std.enums.values(GossipTopic)) |topic| {
            try onGossipHandlers.put(topic, std.ArrayList(OnGossipCbHandler).init(allocator));
        }
        return Self{
            .allocator = allocator,
            .loop = loop,
            .timer = timer,
            .onGossipHandlers = onGossipHandlers,
            .networkId = networkId,
        };
    }

    pub fn onGossip(self: *Self, data: *const GossipMessage, scheduleOnLoop: bool) anyerror!void {
        const topic = data.getTopic();
        const handlerArr = self.onGossipHandlers.get(topic).?;
        std.debug.print("\n\n\nnetwork-{d}:: ongossip handlerArr {any} for topic {any}\n", .{ self.networkId, handlerArr.items, topic });
        for (handlerArr.items) |handler| {

            // TODO: track and dealloc the structures
            const c = try self.allocator.create(xev.Completion);
            c.* = undefined;

            const publishWrapper = try self.allocator.create(MessagePublishWrapper);
            publishWrapper.* = MessagePublishWrapper{ .handler = handler, .data = data, .networkId = self.networkId };
            std.debug.print("\n\n\nnetwork-{d}:: schedueling ongossip publishWrapper={any} on loop for topic {any}\n\n", .{ self.networkId, topic, publishWrapper });

            // TODO: figure out why scheduling on the loop is not working for libp2p separate net instance
            // remove this option once resolved
            if (scheduleOnLoop) {
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
                                std.debug.print("\n\n\n\nnetwork-{d}:: XXXEEEEEEEVVVVVVV ONGOSSIP PUBLISH \n\n\n ", .{pwrap.networkId});
                                _ = pwrap.handler.onGossip(pwrap.data) catch void;
                            }
                            // TODO defer freeing the publishwrapper but need handle to the allocator
                            // also figure out how and when to best dealloc the completion
                            return .disarm;
                        }
                    }).callback,
                );
            } else {
                publishWrapper.handler.onGossip(publishWrapper.data) catch |e| {
                    std.debug.print("\nnetwork-{d}:: onGossip handler error={any}\n", .{ self.networkId, e });
                };
            }
        }
        // we don't need to run the loop as this is a shared loop and is already being run by the clock
    }

    pub fn subscribe(self: *Self, topics: []GossipTopic, handler: OnGossipCbHandler) anyerror!void {
        for (topics) |topic| {
            // handlerarr should already be there
            var handlerArr = self.onGossipHandlers.get(topic).?;
            try handlerArr.append(handler);
            try self.onGossipHandlers.put(topic, handlerArr);
        }
    }
};
