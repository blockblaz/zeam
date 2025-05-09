const std = @import("std");
const Allocator = std.mem.Allocator;

const configs = @import("@zeam/configs");
const types = @import("@zeam/types");

const utils = @import("./utils.zig");
const OnSlotCbWrapper = utils.OnSlotCbWrapper;

pub const fcFactory = @import("./forkchoice.zig");

pub const BeamChain = struct {
    config: configs.ChainConfig,
    forkChoice: fcFactory.ForkChoice,
    allocator: Allocator,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, anchorState: types.BeamState) !Self {
        const fork_choice = try fcFactory.ForkChoice.init(allocator, config, anchorState);
        return Self{
            .config = config,
            .forkChoice = fork_choice,
            .allocator = allocator,
        };
    }

    fn onSlot(ptr: *anyopaque, slot: isize) !void {
        // demonstrate how to call retrive this struct
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.printSlot(slot);
    }

    fn printSlot(self: *Self, slot: isize) void {
        _ = self;
        std.debug.print("chain received on slot cb at slot={d}\n", .{slot});
    }

    pub fn getOnSlotCbWrapper(self: *Self) !*OnSlotCbWrapper {
        // need a stable pointer across threads
        const cb_ptr = try self.allocator.create(OnSlotCbWrapper);
        cb_ptr.* = .{
            .ptr = self,
            .onSlotCb = onSlot,
        };

        return cb_ptr;
    }
};
