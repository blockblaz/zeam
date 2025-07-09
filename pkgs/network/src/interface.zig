pub const GossipSub = struct {
    ptr: *anyopaque,
    publishFn: *const fn (ptr: *anyopaque, comptime T: type, obj: *anyopaque) anyerror!void,
    onGossipFn: *const fn (ptr: *anyopaque, data: []const u8) anyerror!void,
};

pub const ReqResp = struct {
    ptr: *anyopaque,
    reqRespFn: *const fn (ptr: *anyopaque, comptime T: type, obj: *anyopaque) anyerror!void,
    onReqFn: *const fn (ptr: *anyopaque, data: []const u8) anyerror!void,
};

pub const NetworkInterface = struct {
    gossip: GossipSub,
    reqresp: ReqResp,
};
