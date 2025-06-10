const std = @import("std");
const Allocator = std.mem.Allocator;

const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const stf = @import("@zeam/state-transition");
const ssz = @import("ssz");

const utils = @import("./utils.zig");
const OnSlotCbWrapper = utils.OnSlotCbWrapper;

pub const fcFactory = @import("./forkchoice.zig");

pub const BeamChain = struct {
    config: configs.ChainConfig,
    forkChoice: fcFactory.ForkChoice,
    allocator: Allocator,
    // from finalized onwards to recent
    states: std.AutoHashMap(types.Root, types.BeamState),

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, anchorState: types.BeamState) !Self {
        const fork_choice = try fcFactory.ForkChoice.init(allocator, config, anchorState);
        const states = std.AutoHashMap(types.Root, types.BeamState).init(allocator);
        return Self{
            .config = config,
            .forkChoice = fork_choice,
            .allocator = allocator,
            .states = states,
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

    // import block assuming its validated
    fn onBlock(self: *Self, block: types.SignedBeamBlock) !void {
        _ = self;
        _ = block;
        // 1. get parent state
        // 2. STF validation + post state
        // 2. fc onblock
        // 3. fc onvotes
        // 3. fc update head
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

test "build mock chain" {
    // 1. setup genesis config
    const test_config = types.GenesisSpec{
        .genesis_time = 1234,
        .num_validators = 4,
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 5, test_config);
    try std.testing.expect(mock_chain.blocks.len == 5);

    // starting beam state
    var beam_state = mock_chain.genesis_state;
    // block 0 is genesis so we have to apply block 1 onwards
    for (1..mock_chain.blocks.len) |i| {
        // this is a signed block
        const block = mock_chain.blocks[i];
        try stf.apply_transition(allocator, &beam_state, block, .{});
    }

    // check the post state root to be equal to block2's stateroot
    // this is reduant though because apply_transition already checks this for each block's state root
    var post_state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, beam_state, &post_state_root, allocator);
    try std.testing.expect(std.mem.eql(u8, &post_state_root, &mock_chain.blocks[mock_chain.blocks.len - 1].message.state_root));
}
