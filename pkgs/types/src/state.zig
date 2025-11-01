const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");

const block = @import("./block.zig");
const utils = @import("./utils.zig");
const mini_3sf = @import("./mini_3sf.zig");
const validator = @import("./validator.zig");

const Allocator = std.mem.Allocator;
const Attestations = block.Attestations;
const BeamBlock = block.BeamBlock;
const BeamBlockHeader = block.BeamBlockHeader;
const Root = utils.Root;
const Checkpoint = mini_3sf.Checkpoint;
const StateTransitionError = utils.StateTransitionError;
const Slot = utils.Slot;
const Validators = validator.Validators;

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

// Types
pub const HistoricalBlockHashes = ssz.utils.List(Root, params.HISTORICAL_ROOTS_LIMIT);
pub const JustificationRoots = ssz.utils.List(Root, params.HISTORICAL_ROOTS_LIMIT);
pub const JustifiedSlots = ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT);
pub const JustificationValidators = ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT * params.VALIDATOR_REGISTRY_LIMIT);

pub const BeamState = struct {
    config: BeamStateConfig,
    slot: Slot,
    latest_block_header: BeamBlockHeader,

    latest_justified: Checkpoint,
    latest_finalized: Checkpoint,

    historical_block_hashes: HistoricalBlockHashes,
    justified_slots: JustifiedSlots,

    validators: Validators,

    // a flat representation of the justifications map
    justifications_roots: JustificationRoots,
    justifications_validators: JustificationValidators,

    const Self = @This();

    pub fn genGenesisState(self: *Self, allocator: Allocator, genesis: utils.GenesisSpec) !void {
        var genesis_block: block.BeamBlock = undefined;
        try genesis_block.genGenesisBlock(allocator);
        defer genesis_block.deinit();

        var genesis_block_header: block.BeamBlockHeader = undefined;
        try genesis_block.blockToLatestBlockHeader(allocator, &genesis_block_header);

        var historical_block_hashes = try HistoricalBlockHashes.init(allocator);
        errdefer historical_block_hashes.deinit();

        var justified_slots = try JustifiedSlots.init(allocator);
        errdefer justified_slots.deinit();

        var justifications_roots = try ssz.utils.List(utils.Root, params.HISTORICAL_ROOTS_LIMIT).init(allocator);
        errdefer justifications_roots.deinit();

        var justifications_validators = try ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT * params.VALIDATOR_REGISTRY_LIMIT).init(allocator);
        errdefer justifications_validators.deinit();

        var validators = try Validators.init(allocator);
        errdefer validators.deinit();

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
            .validators = validators,
            // justifications map is empty
            .justifications_roots = justifications_roots,
            .justifications_validators = justifications_validators,
        };
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

    pub fn withJustifications(self: *Self, allocator: Allocator, justifications: *const std.AutoHashMapUnmanaged(Root, []u8)) !void {
        var new_justifications_roots = try JustificationRoots.init(allocator);
        errdefer new_justifications_roots.deinit();

        var new_justifications_validators = try JustificationValidators.init(allocator);
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

    fn process_slot(self: *Self, allocator: Allocator) !void {

        // update state root in latest block header if its zero hash
        // i.e. just after processing the latest block of latest block header
        // this completes latest block header for parentRoot checks of new block

        if (std.mem.eql(u8, &self.latest_block_header.state_root, &utils.ZERO_HASH)) {
            var prev_state_root: [32]u8 = undefined;
            try ssz.hashTreeRoot(*BeamState, self, &prev_state_root, allocator);
            self.latest_block_header.state_root = prev_state_root;
        }
    }

    pub fn process_slots(self: *Self, allocator: Allocator, slot: Slot, logger: zeam_utils.ModuleLogger) !void {
        if (slot <= self.slot) {
            logger.err("Invalid block slot={d} >= pre-state slot={d}\n", .{ slot, self.slot });
            return StateTransitionError.InvalidPreState;
        }

        while (self.slot < slot) {
            try self.process_slot(allocator);
            self.slot += 1;
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

    pub fn process_block(self: *Self, allocator: Allocator, staged_block: BeamBlock, logger: zeam_utils.ModuleLogger) !void {
        // start block processing
        try self.process_block_header(allocator, staged_block, logger);
        // PQ devner-0 has no execution
        // try process_execution_payload_header(state, block);
        try self.process_operations(allocator, staged_block, logger);
    }

    fn process_operations(self: *Self, allocator: Allocator, staged_block: BeamBlock, logger: zeam_utils.ModuleLogger) !void {
        // 1. process attestations
        try self.process_attestations(allocator, staged_block.body.attestations, logger);
    }

    fn process_attestations(self: *Self, allocator: Allocator, attestations: Attestations, logger: zeam_utils.ModuleLogger) !void {
        logger.debug("process attestations slot={d} \n prestate:historical hashes={d} justified slots ={d} attestations={d}, ", .{ self.slot, self.historical_block_hashes.len(), self.justified_slots.len(), attestations.constSlice().len });
        const justified_str = try self.latest_justified.toJsonString(allocator);
        defer allocator.free(justified_str);
        const finalized_str = try self.latest_finalized.toJsonString(allocator);
        defer allocator.free(finalized_str);

        logger.debug("prestate justified={s} finalized={s}", .{ justified_str, finalized_str });

        // work directly with SSZ types
        // historical_block_hashes and justified_slots are already SSZ types in state

        var justifications: std.AutoHashMapUnmanaged(Root, []u8) = .empty;
        defer {
            var iterator = justifications.iterator();
            while (iterator.next()) |entry| {
                allocator.free(entry.value_ptr.*);
            }
        }
        errdefer justifications.deinit(allocator);
        try self.getJustification(allocator, &justifications);

        // need to cast to usize for slicing ops but does this makes the STF target arch dependent?
        const num_validators: usize = @intCast(self.config.num_validators);
        for (attestations.constSlice()) |attestation| {
            const validator_id: usize = @intCast(attestation.validator_id);
            const attestation_data = attestation.data;
            // check if attestation is sane
            const source_slot: usize = @intCast(attestation_data.source.slot);
            const target_slot: usize = @intCast(attestation_data.target.slot);
            const attestation_str = try attestation_data.toJsonString(allocator);
            defer allocator.free(attestation_str);

            logger.debug("processing attestation={s} validator_id={d}\n....\n", .{ attestation_str, validator_id });

            if (source_slot >= self.justified_slots.len()) {
                return StateTransitionError.InvalidSlotIndex;
            }
            if (target_slot >= self.justified_slots.len()) {
                return StateTransitionError.InvalidSlotIndex;
            }
            if (source_slot >= self.historical_block_hashes.len()) {
                return StateTransitionError.InvalidSlotIndex;
            }
            if (target_slot >= self.historical_block_hashes.len()) {
                return StateTransitionError.InvalidSlotIndex;
            }

            const is_source_justified = try self.justified_slots.get(source_slot);
            const is_target_already_justified = try self.justified_slots.get(target_slot);
            const has_correct_source_root = std.mem.eql(u8, &attestation_data.source.root, &(try self.historical_block_hashes.get(source_slot)));
            const has_correct_target_root = std.mem.eql(u8, &attestation_data.target.root, &(try self.historical_block_hashes.get(target_slot)));
            const target_not_ahead = target_slot <= source_slot;
            const is_target_justifiable = try utils.IsJustifiableSlot(self.latest_finalized.slot, target_slot);

            if (!is_source_justified or
                // not present in 3sf mini but once a target is justified no need to run loop
                // as we remove the target from justifications map as soon as its justified
                is_target_already_justified or
                !has_correct_source_root or
                !has_correct_target_root or
                target_not_ahead or
                !is_target_justifiable)
            {
                logger.debug("skipping the attestation as not viable: !(source_justified={}) or target_already_justified={} !(correct_source_root={}) or !(correct_target_root={}) or target_not_ahead={} or !(target_justifiable={})", .{
                    is_source_justified,
                    is_target_already_justified,
                    has_correct_source_root,
                    has_correct_target_root,
                    target_not_ahead,
                    is_target_justifiable,
                });
                continue;
            }

            if (validator_id >= num_validators) {
                return StateTransitionError.InvalidValidatorId;
            }

            var target_justifications = justifications.get(attestation_data.target.root) orelse targetjustifications: {
                var targetjustifications = try allocator.alloc(u8, num_validators);
                for (0..targetjustifications.len) |i| {
                    targetjustifications[i] = 0;
                }
                try justifications.put(allocator, attestation_data.target.root, targetjustifications);
                break :targetjustifications targetjustifications;
            };

            target_justifications[validator_id] = 1;
            try justifications.put(allocator, attestation_data.target.root, target_justifications);
            var target_justifications_count: usize = 0;
            for (target_justifications) |justified| {
                if (justified == 1) {
                    target_justifications_count += 1;
                }
            }
            logger.debug("target jcount={d}: {any} justifications={any}\n", .{ target_justifications_count, attestation_data.target.root, target_justifications });

            // as soon as we hit the threshold do justifications
            // note that this simplification works if weight of each validator is 1
            //
            // ceilDiv is not available so this seems like a less compute intensive way without
            // requring float division, can be further optimized
            if (3 * target_justifications_count >= 2 * num_validators) {
                self.latest_justified = attestation_data.target;
                try self.justified_slots.set(target_slot, true);
                _ = justifications.remove(attestation_data.target.root);
                const justified_str_new = try self.latest_justified.toJsonString(allocator);
                defer allocator.free(justified_str_new);

                logger.debug("\n\n\n-----------------HURRAY JUSTIFICATION ------------\n{s}\n--------------\n---------------\n-------------------------\n\n\n", .{justified_str_new});

                // source is finalized if target is the next valid justifiable hash
                var can_target_finalize = true;
                for (source_slot + 1..target_slot) |check_slot| {
                    if (try utils.IsJustifiableSlot(self.latest_finalized.slot, check_slot)) {
                        can_target_finalize = false;
                        break;
                    }
                }
                logger.debug("----------------can_target_finalize ({d})={any}----------\n\n", .{ source_slot, can_target_finalize });
                if (can_target_finalize == true) {
                    self.latest_finalized = attestation_data.source;
                    const finalized_str_new = try self.latest_finalized.toJsonString(allocator);
                    defer allocator.free(finalized_str_new);

                    logger.debug("\n\n\n-----------------DOUBLE HURRAY FINALIZATION ------------\n{s}\n--------------\n---------------\n-------------------------\n\n\n", .{finalized_str_new});
                }
            }
        }

        try self.withJustifications(allocator, &justifications);

        logger.debug("poststate:historical hashes={d} justified slots ={d}\n justifications_roots:{d}\n justifications_validators={d}\n", .{ self.historical_block_hashes.len(), self.justified_slots.len(), self.justifications_roots.len(), self.justifications_validators.len() });
        const justified_str_final = try self.latest_justified.toJsonString(allocator);
        defer allocator.free(justified_str_final);
        const finalized_str_final = try self.latest_finalized.toJsonString(allocator);
        defer allocator.free(finalized_str_final);

        logger.debug("poststate: justified={s} finalized={s}", .{ justified_str_final, finalized_str_final });
    }

    pub fn genGenesisBlock(self: *const Self, allocator: Allocator, genesis_block: *block.BeamBlock) !void {
        var state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            BeamState,
            self.*,
            &state_root,
            allocator,
        );

        const attestations = try Attestations.init(allocator);
        errdefer attestations.deinit();

        genesis_block.* = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = utils.ZERO_HASH,
            .state_root = state_root,
            .body = .{
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
        self.validators.deinit();
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

        // Serialize validators
        var validators_array = json.Array.init(allocator);
        for (self.validators.constSlice()) |val| {
            try validators_array.append(try val.toJson(allocator));
        }
        try obj.put("validators", json.Value{ .array = validators_array });

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
        .historical_block_hashes = try HistoricalBlockHashes.init(std.testing.allocator),
        .justified_slots = try JustifiedSlots.init(std.testing.allocator),
        .validators = try Validators.init(std.testing.allocator),
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
