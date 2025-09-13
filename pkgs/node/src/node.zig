const std = @import("std");
const Allocator = std.mem.Allocator;

const params = @import("@zeam/params");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const networks = @import("@zeam/network");
const zeam_utils = @import("@zeam/utils");

const utils = @import("./utils.zig");
const OnIntervalCbWrapper = utils.OnIntervalCbWrapper;

pub const chainFactory = @import("./chain.zig");
pub const clockFactory = @import("./clock.zig");
pub const networkFactory = @import("./network.zig");
pub const validators = @import("./validator.zig");

// TODO: find a in mem level db for this
const LevelDB = struct {};

const NodeOpts = struct {
    config: configs.ChainConfig,
    anchorState: types.BeamState,
    backend: networks.NetworkInterface,
    clock: *clockFactory.Clock,
    db: LevelDB,
    validator_ids: ?[]usize = null,
    nodeId: u32 = 0,
    logger: *zeam_utils.ZeamLogger,
};

pub const BeamNode = struct {
    allocator: Allocator,
    clock: *clockFactory.Clock,
    chain: *chainFactory.BeamChain,
    network: networkFactory.Network,
    validator: ?validators.BeamValidator = null,
    nodeId: u32,
    logger: *const zeam_utils.ZeamLogger,

    const Self = @This();
    pub fn init(allocator: Allocator, opts: NodeOpts) !Self {
        var validator: ?validators.BeamValidator = null;

        const chain = try allocator.create(chainFactory.BeamChain);
        const network = networkFactory.Network.init(opts.backend);

        chain.* = try chainFactory.BeamChain.init(allocator, opts.config, opts.anchorState, opts.nodeId, opts.logger);
        if (opts.validator_ids) |ids| {
            validator = validators.BeamValidator.init(allocator, opts.config, .{ .ids = ids, .chain = chain, .network = network, .logger = opts.logger });
            chain.registerValidatorIds(ids);
        }

        return Self{
            .allocator = allocator,
            .clock = opts.clock,
            .chain = chain,
            .network = network,
            .validator = validator,
            .nodeId = opts.nodeId,
            .logger = opts.logger,
        };
    }

    pub fn onGossip(ptr: *anyopaque, data: *const networks.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        try self.chain.onGossip(data);
    }

    pub fn getOnGossipCbHandler(self: *Self) !networks.OnGossipCbHandler {
        return .{
            .ptr = self,
            .onGossipCb = onGossip,
        };
    }

    pub fn getOnIntervalCbWrapper(self: *Self) !*OnIntervalCbWrapper {
        // need a stable pointer across threads
        const cb_ptr = try self.allocator.create(OnIntervalCbWrapper);
        cb_ptr.* = .{
            .ptr = self,
            .onIntervalCb = onInterval,
        };

        return cb_ptr;
    }

    pub fn onInterval(ptr: *anyopaque, iinterval: isize) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const interval: usize = @intCast(iinterval);

        self.chain.onInterval(interval) catch |e| {
            self.logger.err("Error ticking chain to time(intervals)={d} err={any}", .{ interval, e });
            // no point going further if chain is not ticked properly
            return e;
        };
        if (self.validator) |*validator| {
            // we also tick validator per interval in case it would
            // need to sync its future duties when its an independent validator
            validator.onInterval(interval) catch |e| {
                self.logger.err("Error ticking validator to time(intervals)={d} err={any}", .{ interval, e });
                return e;
            };
        }
    }

    pub fn run(self: *Self) !void {
        const handler = try self.getOnGossipCbHandler();
        var topics = [_]networks.GossipTopic{ .block, .vote };
        try self.network.backend.gossip.subscribe(&topics, handler);

        const chainOnSlot = try self.getOnIntervalCbWrapper();
        try self.clock.subscribeOnSlot(chainOnSlot);
    }
};
