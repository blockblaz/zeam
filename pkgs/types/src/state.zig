const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");

const block = @import("./block.zig");
const utils = @import("./utils.zig");
const mini_3sf = @import("./mini_3sf.zig");

const Allocator = std.mem.Allocator;
const Root = utils.Root;
const Mini3SFCheckpoint = mini_3sf.Mini3SFCheckpoint;
const HistoricalBlockHashes = utils.HistoricalBlockHashes;
const JustifiedSlots = utils.JustifiedSlots;
const JustificationsRoots = utils.JustificationsRoots;
const JustificationsValidators = utils.JustificationsValidators;
const StateTransitionError = utils.StateTransitionError;

const bytesToHex = utils.BytesToHex;
const json = std.json;

// PQ devnet0 config
pub const BeamStateConfig = struct {
    num_validators: u64,
    genesis_time: u64,

    pub fn toJson(self: *const BeamStateConfig, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("num_validators", json.Value{ .integer = @as(i64, @intCast(self.num_validators)) });
        try obj.put("genesis_time", json.Value{ .integer = @as(i64, @intCast(self.genesis_time)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamStateConfig, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BeamState = struct {
    config: BeamStateConfig,
    slot: u64,
    latest_block_header: block.BeamBlockHeader,

    latest_justified: Mini3SFCheckpoint,
    latest_finalized: Mini3SFCheckpoint,

    historical_block_hashes: HistoricalBlockHashes,
    justified_slots: JustifiedSlots,

    // a flat representation of the justifications map
    justifications_roots: JustificationsRoots,
    justifications_validators: JustificationsValidators,

    const Self = @This();

    pub fn withJustifications(self: *Self, allocator: Allocator, justifications: *const std.AutoHashMapUnmanaged(Root, []u8)) !void {
        var new_justifications_roots = try JustificationsRoots.init(allocator);
        errdefer new_justifications_roots.deinit();

        var new_justifications_validators = try JustificationsValidators.init(allocator);
        errdefer new_justifications_validators.deinit();

        // First, collect all keys
        var iterator = justifications.iterator();
        while (iterator.next()) |kv| {
            if (kv.value_ptr.*.len != self.config.num_validators) {
                return error.InvalidJustificationLength;
            }
            try new_justifications_roots.append(kv.key_ptr.*);
        }

        // Sort the roots, confirm this sorting via a test
        std.mem.sortUnstable(Root, new_justifications_roots.slice(), {}, struct {
            fn lessThanFn(_: void, a: Root, b: Root) bool {
                return std.mem.order(u8, &a, &b) == .lt;
            }
        }.lessThanFn);

        // Now iterate over sorted roots and flatten validators in order
        for (new_justifications_roots.constSlice()) |root| {
            const rootSlice = justifications.get(root) orelse unreachable;
            // append individual bits for validator justifications
            // have a batch set method to set it since eventual num vals are div by 8
            // and hence the vector can be fully appeneded as bytes
            for (rootSlice) |validator_bit| {
                try new_justifications_validators.append(validator_bit == 1);
            }
        }

        // Lists are now heap allocated ArrayLists using the allocator
        // Deinit existing lists and reinitialize
        self.justifications_roots.deinit();
        self.justifications_validators.deinit();
        self.justifications_roots = new_justifications_roots;
        self.justifications_validators = new_justifications_validators;
    }

    pub fn getJustification(self: *const Self, allocator: Allocator, justifications: *std.AutoHashMapUnmanaged(Root, []u8)) !void {
        // need to cast to usize for slicing ops but does this makes the STF target arch dependent?
        const num_validators: usize = @intCast(self.config.num_validators);
        // Initialize justifications from state
        for (self.justifications_roots.constSlice(), 0..) |blockRoot, i| {
            const validator_data = try allocator.alloc(u8, num_validators);
            errdefer allocator.free(validator_data);
            // Copy existing justification data if available, otherwise return error
            for (validator_data, 0..) |*byte, j| {
                const bit_index = i * num_validators + j;
                byte.* = if (try self.justifications_validators.get(bit_index)) 1 else 0;
            }
            try justifications.put(allocator, blockRoot, validator_data);
        }
    }

    pub fn process_block_header(self: *Self, allocator: Allocator, staged_block: block.BeamBlock, logger: zeam_utils.ModuleLogger) !void {
        logger.debug("processing beam block header\n", .{});

        // 1. match state and block slot
        if (self.slot != staged_block.slot) {
            logger.err("process-block-header: invalid mismatching state-slot={} != block-slot={}", .{ self.slot, staged_block.slot });
            return StateTransitionError.InvalidPreState;
        }

        // 2. match state's latest block header and block slot
        if (self.latest_block_header.slot >= staged_block.slot) {
            logger.err("process-block-header: invalid future latest_block_header-slot={} >= block-slot={}", .{ self.latest_block_header.slot, staged_block.slot });
            return StateTransitionError.InvalidLatestBlockHeader;
        }

        // 3. check proposer is correct
        const correct_proposer_index = staged_block.slot % self.config.num_validators;
        if (staged_block.proposer_index != correct_proposer_index) {
            logger.err("process-block-header: invalid proposer={d} slot={d} correct-proposer={d}", .{ staged_block.proposer_index, staged_block.slot, correct_proposer_index });
            return StateTransitionError.InvalidProposer;
        }

        // 4. verify latest block header is the parent
        var head_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(block.BeamBlockHeader, self.latest_block_header, &head_root, allocator);
        if (!std.mem.eql(u8, &head_root, &staged_block.parent_root)) {
            logger.err("state root={x:02} block root={x:02}\n", .{ head_root, staged_block.parent_root });
            return StateTransitionError.InvalidParentRoot;
        }

        // update justified and finalized with parent root in state if this is the first block post genesis
        if (self.latest_block_header.slot == 0) {
            // fixed  length array structures should just be copied over
            self.latest_justified.root = staged_block.parent_root;
            self.latest_finalized.root = staged_block.parent_root;
        }

        // extend historical block hashes and justified slots structures using SSZ Lists directly
        try self.historical_block_hashes.append(staged_block.parent_root);
        // if parent is genesis it is already justified
        try self.justified_slots.append(if (self.latest_block_header.slot == 0) true else false);

        const block_slot: usize = @intCast(staged_block.slot);
        const missed_slots: usize = @intCast(block_slot - self.latest_block_header.slot - 1);
        for (0..missed_slots) |i| {
            _ = i;
            try self.historical_block_hashes.append(utils.ZERO_HASH);
            try self.justified_slots.append(false);
        }
        logger.debug("processed missed_slots={d} justified_slots={any}, historical_block_hashes={any}", .{ missed_slots, self.justified_slots.len(), self.historical_block_hashes.len() });

        try staged_block.blockToLatestBlockHeader(allocator, &self.latest_block_header);
    }

    pub fn genGenesisState(self: *Self, allocator: Allocator, genesis: utils.GenesisSpec) !void {
        var genesis_block: block.BeamBlock = undefined;
        try genesis_block.genGenesisBlock(allocator);
        defer genesis_block.deinit();

        var genesis_block_header: block.BeamBlockHeader = undefined;
        try genesis_block.blockToLatestBlockHeader(allocator, &genesis_block_header);

        var historical_block_hashes = try utils.HistoricalBlockHashes.init(allocator);
        errdefer historical_block_hashes.deinit();

        var justified_slots = try utils.JustifiedSlots.init(allocator);
        errdefer justified_slots.deinit();

        var justifications_roots = try ssz.utils.List(utils.Root, params.HISTORICAL_ROOTS_LIMIT).init(allocator);
        errdefer justifications_roots.deinit();

        var justifications_validators = try ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT * params.VALIDATOR_REGISTRY_LIMIT).init(allocator);
        errdefer justifications_validators.deinit();

        self.* = .{
            .config = .{
                .num_validators = genesis.num_validators,
                .genesis_time = genesis.genesis_time,
            },
            .slot = 0,
            .latest_block_header = genesis_block_header,
            // mini3sf
            .latest_justified = .{ .root = [_]u8{0} ** 32, .slot = 0 },
            .latest_finalized = .{ .root = [_]u8{0} ** 32, .slot = 0 },
            .historical_block_hashes = historical_block_hashes,
            .justified_slots = justified_slots,
            // justifications map is empty
            .justifications_roots = justifications_roots,
            .justifications_validators = justifications_validators,
        };
    }

    pub fn genGenesisBlock(self: *const Self, allocator: Allocator, genesis_block: *block.BeamBlock) !void {
        var state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            BeamState,
            self.*,
            &state_root,
            allocator,
        );

        const attestations = try mini_3sf.SignedVotes.init(allocator);
        errdefer attestations.deinit();

        genesis_block.* = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = utils.ZERO_HASH,
            .state_root = state_root,
            .body = .{
                // .execution_payload_header = .{ .timestamp = 0 },
                // 3sf mini
                .attestations = attestations,
            },
        };
    }

    pub fn genStateBlockHeader(self: *const Self, allocator: Allocator) !block.BeamBlockHeader {
        // check does it need cloning?
        var beam_block_header = self.latest_block_header;
        var state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            BeamState,
            self.*,
            &state_root,
            allocator,
        );
        beam_block_header.state_root = state_root;

        return beam_block_header;
    }

    pub fn deinit(self: *Self) void {
        // Deinit heap allocated ArrayLists
        self.historical_block_hashes.deinit();
        self.justified_slots.deinit();
        self.justifications_roots.deinit();
        self.justifications_validators.deinit();
    }

    pub fn toJson(self: *const BeamState, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("config", try self.config.toJson(allocator));
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("latest_block_header", try self.latest_block_header.toJson(allocator));
        try obj.put("latest_justified", try self.latest_justified.toJson(allocator));
        try obj.put("latest_finalized", try self.latest_finalized.toJson(allocator));

        // Serialize historical_block_hashes
        var historical_hashes_array = json.Array.init(allocator);
        for (self.historical_block_hashes.constSlice()) |hash| {
            try historical_hashes_array.append(json.Value{ .string = try bytesToHex(allocator, &hash) });
        }
        try obj.put("historical_block_hashes", json.Value{ .array = historical_hashes_array });

        // Serialize justified_slots as array of booleans
        var justified_slots_array = json.Array.init(allocator);
        for (0..self.justified_slots.len()) |i| {
            try justified_slots_array.append(json.Value{ .bool = try self.justified_slots.get(i) });
        }
        try obj.put("justified_slots", json.Value{ .array = justified_slots_array });

        // Serialize justifications_roots
        var justifications_roots_array = json.Array.init(allocator);
        for (self.justifications_roots.constSlice()) |root| {
            try justifications_roots_array.append(json.Value{ .string = try bytesToHex(allocator, &root) });
        }
        try obj.put("justifications_roots", json.Value{ .array = justifications_roots_array });

        // Serialize justifications_validators as array of booleans
        var justifications_validators_array = json.Array.init(allocator);
        for (0..self.justifications_validators.len()) |i| {
            try justifications_validators_array.append(json.Value{ .bool = try self.justifications_validators.get(i) });
        }
        try obj.put("justifications_validators", json.Value{ .array = justifications_validators_array });

        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamState, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

test "ssz seralize/deserialize signed beam state" {
    const config = BeamStateConfig{ .num_validators = 4, .genesis_time = 93 };
    const genesis_root = [_]u8{9} ** 32;

    var state = BeamState{
        .config = config,
        .slot = 99,
        .latest_block_header = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = [_]u8{1} ** 32,
            .state_root = [_]u8{2} ** 32,
            .body_root = [_]u8{3} ** 32,
        },
        // mini3sf
        .latest_justified = .{ .root = [_]u8{5} ** 32, .slot = 0 },
        .latest_finalized = .{ .root = [_]u8{4} ** 32, .slot = 0 },
        .historical_block_hashes = try utils.HistoricalBlockHashes.init(std.testing.allocator),
        .justified_slots = try JustifiedSlots.init(std.testing.allocator),
        .justifications_roots = blk: {
            var roots = try ssz.utils.List(Root, params.HISTORICAL_ROOTS_LIMIT).init(std.testing.allocator);
            try roots.append(genesis_root);
            break :blk roots;
        },
        .justifications_validators = blk: {
            var validators = try ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT * params.VALIDATOR_REGISTRY_LIMIT).init(std.testing.allocator);
            try validators.append(true);
            try validators.append(false);
            try validators.append(true);
            break :blk validators;
        },
    };
    defer state.deinit();

    var serialized_state = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_state.deinit();
    try ssz.serialize(BeamState, state, &serialized_state);
    std.debug.print("\n\n\nserialized_state ({d})", .{serialized_state.items.len});

    // we need to use arena allocator because deserialization allocs without providing for
    // a way to deinit, this needs to be probably addressed in ssz
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    var deserialized_state: BeamState = undefined;
    try ssz.deserialize(BeamState, serialized_state.items[0..], &deserialized_state, arena_allocator.allocator());
    try std.testing.expect(state.justifications_validators.eql(&deserialized_state.justifications_validators));

    // successful merklization
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        BeamState,
        state,
        &state_root,
        std.testing.allocator,
    );
}
