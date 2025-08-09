const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const xev = @import("xev");

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

const MockPublishWrapper = struct {
    handler: interface.OnGossipCbHandler,
    data: *const interface.GossipMessage,
};

pub const Mock = struct {
    loop: *xev.Loop,
    timer: xev.Timer,
    allocator: Allocator,
    onGossipHandlers: std.AutoHashMap(interface.GossipTopic, std.ArrayList(interface.OnGossipCbHandler)),

    const Self = @This();

    pub fn init(allocator: Allocator, loop: *xev.Loop) !Self {
        const timer = try xev.Timer.init();

        var onGossipHandlers = std.AutoHashMap(interface.GossipTopic, std.ArrayList(interface.OnGossipCbHandler)).init(allocator);
        for (std.enums.values(interface.GossipTopic)) |topic| {
            try onGossipHandlers.put(topic, std.ArrayList(interface.OnGossipCbHandler).init(allocator));
        }
        return Self{
            .allocator = allocator,
            .loop = loop,
            .timer = timer,
            .onGossipHandlers = onGossipHandlers,
        };
    }

    pub fn publish(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        // TODO: prevent from publishing to self handler
        return Self.onGossip(ptr, data);
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        for (topics) |topic| {
            // handlerarr should already be there
            var handlerArr = self.onGossipHandlers.get(topic).?;
            try handlerArr.append(handler);
            try self.onGossipHandlers.put(topic, handlerArr);
        }
    }

    pub fn onGossip(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const topic = data.getTopic();
        const handlerArr = self.onGossipHandlers.get(topic).?;
        std.debug.print("\n\n\n ongossip handlerarr {any} for topic {any}\n", .{ handlerArr.items, topic });
        for (handlerArr.items) |handler| {

            // TODO: track and dealloc the structures
            const c = try self.allocator.create(xev.Completion);
            c.* = undefined;

            const publishWrapper = try self.allocator.create(MockPublishWrapper);
            publishWrapper.* = MockPublishWrapper{ .handler = handler, .data = data };

            self.timer.run(
                self.loop,
                c,
                1,
                MockPublishWrapper,
                publishWrapper,
                (struct {
                    fn callback(
                        ud: ?*MockPublishWrapper,
                        _: *xev.Loop,
                        _: *xev.Completion,
                        r: xev.Timer.RunError!void,
                    ) xev.CallbackAction {
                        _ = r catch unreachable;
                        if (ud) |pwrap| {
                            std.debug.print("\n\n\n\n XXXEEEEEEEVVVVVVV ONGOSSIP PUBLISH \n\n\n ", .{});
                            _ = pwrap.handler.onGossip(pwrap.data) catch void;
                        }
                        // TODO defer freeing the publishwrapper but need handle to the allocator
                        // also figure out how and when to best dealloc the completion
                        return .disarm;
                    }
                }).callback,
            );
        }
        // we don't need to run the loop as this is a shared loop and is already being run by the clock
    }

    pub fn reqResp(ptr: *anyopaque, obj: *interface.ReqRespRequest) anyerror!void {
        _ = ptr;
        _ = obj;
    }

    pub fn onReq(ptr: *anyopaque, data: *interface.ReqRespRequest) anyerror!void {
        _ = ptr;
        _ = data;
    }

    pub fn getNetworkInterface(self: *Self) NetworkInterface {
        return .{ .gossip = .{
            .ptr = self,
            .publishFn = publish,
            .subscribeFn = subscribe,
            .onGossipFn = onGossip,
        }, .reqresp = .{
            .ptr = self,
            .reqRespFn = reqResp,
            .onReqFn = onReq,
        } };
    }
};
