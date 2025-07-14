pub const GossipSub = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    publishFn: *const fn (ptr: *anyopaque, obj: *anyopaque) anyerror!void,
    subscribeFn: *const fn (ptr: *anyopaque, topic: []const u8, handler: OnGossipCbHandler) anyerror!void,
    onGossipFn: *const fn (ptr: *anyopaque, data: []const u8) anyerror!void,

    pub fn subscribe(self: GossipSub, topic: []const u8, handler: OnGossipCbHandler) anyerror!void {
        return self.subscribeFn(self.ptr, topic, handler);
    }
};

pub const ReqResp = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    reqRespFn: *const fn (ptr: *anyopaque, obj: *anyopaque) anyerror!void,
    onReqFn: *const fn (ptr: *anyopaque, data: []const u8) anyerror!void,
};

pub const NetworkInterface = struct {
    gossip: GossipSub,
    reqresp: ReqResp,
};

const OnGossipCbType = *const fn (*anyopaque, []const u8) anyerror!void;
pub const OnGossipCbHandler = struct {
    ptr: *anyopaque,
    onGossipCb: OnGossipCbType,
    // c: xev.Completion = undefined,

    pub fn onGossip(self: OnGossipCbHandler, data: []const u8) anyerror!void {
        return self.onGossipCb(self.ptr, data);
    }
};
