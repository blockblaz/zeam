const types = @import("@zeam/types");

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
};
pub const GossipMessage = union(GossipTopic) {
    block: types.SignedBeamBlock,

    const Self = @This();
    // figureout is there a generic way to find active enum
    pub fn getTopic(self: *const Self) GossipTopic {
        switch (self.*) {
            .block => return .block,
        }
    }
};

pub const ReqRespMethod = enum {
    block_by_root,
};
pub const ReqRespRequest = union(ReqRespMethod) {
    block_by_root: types.BlockByRootRequest,
};
