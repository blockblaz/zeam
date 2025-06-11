const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

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
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    const mock_chain = try stf.genMockChain(allocator, 2, chain_config.genesis);
    var beam_state = mock_chain.genesis_state;
    var beam_chain = try BeamChain.init(allocator, chain_config, beam_state);

    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.finalizedRoot, &mock_chain.blockRoots[0]));
    try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.finalizedRoot, &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));
    try std.testing.expect(std.mem.eql(u8, mock_chain.blocks[0].message.state_root[0..], &beam_chain.forkChoice.protoArray.nodes.items[0].stateRoot));
    try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[0], &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));

    for (1..mock_chain.blocks.len) |i| {
        // get the block post state
        const block = mock_chain.blocks[i];
        try stf.apply_transition(allocator, &beam_state, block, .{});

        // shouldn't accept a future slot
        const current_slot = block.message.slot;
        try std.testing.expectError(error.FutureSlot, beam_chain.forkChoice.onBlock(block.message, beam_state, .{ .currentSlot = current_slot, .blockDelayMs = 0 }));

        beam_chain.forkChoice.tickSlot(current_slot);
        try beam_chain.forkChoice.onBlock(block.message, beam_state, .{ .currentSlot = block.message.slot, .blockDelayMs = 0 });
        try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &beam_chain.forkChoice.protoArray.nodes.items[i].blockRoot));

        const searched_idx = beam_chain.forkChoice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);
    }
}
