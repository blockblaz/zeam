const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const ssz = @import("ssz");
const params = @import("@zeam/params");
const utils = @import("@zeam/utils");

// Helper function to convert bytes to hex string
fn bytesToHex(allocator: Allocator, bytes: []const u8) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(bytes)});
}

// just dummy type right now to test imports
pub const Bytes32 = [32]u8;
pub const Slot = u64;
pub const Interval = u64;
pub const ValidatorIndex = u64;
pub const Bytes48 = [48]u8;

pub const SIGSIZE = 4000;
pub const Bytes4000 = [SIGSIZE]u8;

pub const Root = Bytes32;
// zig treats string as byte sequence so hex is 64 bytes string
pub const RootHex = [64]u8;

pub const ZERO_HASH = [_]u8{0x00} ** 32;

pub const BeamBlockHeader = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body_root: Bytes32,

    pub fn toJson(self: *const BeamBlockHeader, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("proposer_index", json.Value{ .integer = @as(i64, @intCast(self.proposer_index)) });
        try obj.put("parent_root", json.Value{ .string = try bytesToHex(allocator, &self.parent_root) });
        try obj.put("state_root", json.Value{ .string = try bytesToHex(allocator, &self.state_root) });
        try obj.put("body_root", json.Value{ .string = try bytesToHex(allocator, &self.body_root) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamBlockHeader, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

// basic payload header for some sort of APS
pub const ExecutionPayloadHeader = struct {
    timestamp: u64,

    pub fn toJson(self: *const ExecutionPayloadHeader, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("timestamp", json.Value{ .integer = @as(i64, @intCast(self.timestamp)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const ExecutionPayloadHeader, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const Mini3SFCheckpoint = struct {
    root: Root,
    slot: Slot,

    pub fn toJson(self: *const Mini3SFCheckpoint, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("root", json.Value{ .string = try bytesToHex(allocator, &self.root) });
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Mini3SFCheckpoint, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const Mini3SFVote = struct {
    slot: Slot,
    head: Mini3SFCheckpoint,
    target: Mini3SFCheckpoint,
    source: Mini3SFCheckpoint,

    pub fn toJson(self: *const Mini3SFVote, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("head", try self.head.toJson(allocator));
        try obj.put("target", try self.target.toJson(allocator));
        try obj.put("source", try self.source.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Mini3SFVote, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

// this will be updated to correct impl in the followup PR to reflect latest spec changes
pub const SignedVote = struct {
    validator_id: u64,
    message: Mini3SFVote,
    // TODO signature objects to be updated in a followup PR
    signature: Bytes4000,

    pub fn toJson(self: *const SignedVote, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("validator_id", json.Value{ .integer = @as(i64, @intCast(self.validator_id)) });
        try obj.put("message", try self.message.toJson(allocator));
        try obj.put("signature", json.Value{ .string = try bytesToHex(allocator, &self.signature) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedVote, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};
pub const Mini3SFVotes = ssz.utils.List(Mini3SFVote, params.VALIDATOR_REGISTRY_LIMIT);
pub const SignedVotes = ssz.utils.List(SignedVote, params.VALIDATOR_REGISTRY_LIMIT);

/// Canonical lightweight forkchoice proto block used across modules
pub const ProtoBlock = struct {
    slot: Slot,
    blockRoot: Root,
    parentRoot: Root,
    stateRoot: Root,
    timeliness: bool,

    pub fn toJson(self: *const ProtoBlock, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("blockRoot", json.Value{ .string = try bytesToHex(allocator, &self.blockRoot) });
        try obj.put("parentRoot", json.Value{ .string = try bytesToHex(allocator, &self.parentRoot) });
        try obj.put("stateRoot", json.Value{ .string = try bytesToHex(allocator, &self.stateRoot) });
        try obj.put("timeliness", json.Value{ .bool = self.timeliness });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const ProtoBlock, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BeamBlockBody = struct {
    // some form of APS - to be activated later - disabled for PQ devnet0
    // execution_payload_header: ExecutionPayloadHeader,

    // mini 3sf simplified votes
    attestations: SignedVotes,

    pub fn deinit(self: *BeamBlockBody) void {
        // Deinit heap allocated ArrayLists
        self.attestations.deinit();
    }

    pub fn toJson(self: *const BeamBlockBody, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);

        // Serialize attestations list
        var attestations_array = json.Array.init(allocator);
        for (self.attestations.constSlice()) |attestation| {
            try attestations_array.append(try attestation.toJson(allocator));
        }
        try obj.put("attestations", json.Value{ .array = attestations_array });

        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamBlockBody, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BeamBlock = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body: BeamBlockBody,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.body.deinit();
    }

    pub fn genGenesisBlock(self: *Self, allocator: Allocator) !void {
        const attestations = try SignedVotes.init(allocator);
        errdefer attestations.deinit();

        self.* = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = ZERO_HASH,
            .state_root = ZERO_HASH,
            .body = .{
                // .execution_payload_header = .{ .timestamp = 0 },
                // 3sf mini votes
                .attestations = attestations,
            },
        };
    }

    // computing latest block header to be assigned to the state for processing the block
    pub fn blockToLatestBlockHeader(self: *const Self, allocator: Allocator, header: *BeamBlockHeader) !void {
        var body_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            BeamBlockBody,
            self.body,
            &body_root,
            allocator,
        );

        header.* = .{
            .slot = self.slot,
            .proposer_index = self.proposer_index,
            .parent_root = self.parent_root,
            .state_root = ZERO_HASH,
            .body_root = body_root,
        };
    }

    pub fn toJson(self: *const BeamBlock, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("proposer_index", json.Value{ .integer = @as(i64, @intCast(self.proposer_index)) });
        try obj.put("parent_root", json.Value{ .string = try bytesToHex(allocator, &self.parent_root) });
        try obj.put("state_root", json.Value{ .string = try bytesToHex(allocator, &self.state_root) });
        try obj.put("body", try self.body.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamBlock, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const SignedBeamBlock = struct {
    message: BeamBlock,
    // winternitz signature might be of different size depending on num chunks and chunk size
    signature: Bytes4000,
    pub fn deinit(self: *SignedBeamBlock) void {
        // Deinit heap allocated ArrayLists
        self.message.body.attestations.deinit();
    }

    pub fn toJson(self: *const SignedBeamBlock, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("message", try self.message.toJson(allocator));
        try obj.put("signature", json.Value{ .string = try bytesToHex(allocator, &self.signature) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedBeamBlock, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

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

pub const HistoricalBlockHashes = ssz.utils.List(Root, params.HISTORICAL_ROOTS_LIMIT);
pub const JustifiedSlots = ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT);
pub const JustificationsRoots = ssz.utils.List(Root, params.HISTORICAL_ROOTS_LIMIT);
pub const JustificationsValidators = ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT * params.VALIDATOR_REGISTRY_LIMIT);
// array of array ssz needs to be also figured out
// implement justification map as flat array of keys, with flatted corresponding
// justifications of num_validators each, which isn't an issue for now because
// we will keep it constant
// pub const Justifications = struct {
//     roots: []Root,
//     voting_validators: []u8,
// };
pub const BeamState = struct {
    config: BeamStateConfig,
    slot: u64,
    latest_block_header: BeamBlockHeader,

    latest_justified: Mini3SFCheckpoint,
    latest_finalized: Mini3SFCheckpoint,

    historical_block_hashes: HistoricalBlockHashes,
    justified_slots: JustifiedSlots,

    // a flat representation of the justifications map
    justifications_roots: JustificationsRoots,
    justifications_validators: JustificationsValidators,

    pub fn deinit(self: *BeamState) void {
        // Deinit heap allocated ArrayLists
        self.historical_block_hashes.deinit();
        self.justified_slots.deinit();
        self.justifications_roots.deinit();
        self.justifications_validators.deinit();
    }

    pub fn withJustifications(self: *BeamState, allocator: Allocator, justifications: *const std.AutoHashMapUnmanaged(Root, []u8)) !void {
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

    pub fn getJustification(self: *const BeamState, allocator: Allocator, justifications: *std.AutoHashMapUnmanaged(Root, []u8)) !void {
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

    /// Helper function to check if a slot is justifiable after finalization
    pub fn isJustifiableSlot(finalized: Slot, candidate: Slot) !bool {
        if (candidate < finalized) {
            return error.InvalidJustifiableSlot;
        }

        const delta: f32 = @floatFromInt(candidate - finalized);
        if (delta <= 5) {
            return true;
        }
        const delta_x2: f32 = @mod(std.math.pow(f32, delta, 0.5), 1);
        if (delta_x2 == 0) {
            return true;
        }
        const delta_x2_x: f32 = @mod(std.math.pow(f32, delta + 0.25, 0.5), 1);
        if (delta_x2_x == 0.5) {
            return true;
        }

        return false;
    }

    /// Process attestations and update justification/finalization state
    /// Following leanSpec style: member function that operates on self
    pub fn processAttestations(self: *BeamState, allocator: Allocator, attestations: SignedVotes, logger: utils.ModuleLogger) !void {
        logger.debug("process attestations slot={d} \n prestate:historical hashes={d} justified slots ={d} votes={d}, ", .{ self.slot, self.historical_block_hashes.len(), self.justified_slots.len(), attestations.constSlice().len });
        const justified_str = try self.latest_justified.toJsonString(allocator);
        defer allocator.free(justified_str);
        const finalized_str = try self.latest_finalized.toJsonString(allocator);
        defer allocator.free(finalized_str);

        logger.debug("prestate justified={s} finalized={s}", .{ justified_str, finalized_str });

        // Get current justifications from state
        var justifications: std.AutoHashMapUnmanaged(Root, []u8) = .empty;
        defer {
            var iterator = justifications.iterator();
            while (iterator.next()) |entry| {
                allocator.free(entry.value_ptr.*);
            }
        }
        errdefer justifications.deinit(allocator);
        try self.getJustification(allocator, &justifications);

        const num_validators: usize = @intCast(self.config.num_validators);

        // Process each attestation
        for (attestations.constSlice()) |signed_vote| {
            const validator_id: usize = @intCast(signed_vote.validator_id);
            const vote = signed_vote.message;

            // Validate vote structure
            const source_slot: usize = @intCast(vote.source.slot);
            const target_slot: usize = @intCast(vote.target.slot);
            const vote_str = try vote.toJsonString(allocator);
            defer allocator.free(vote_str);

            logger.debug("processing vote={s} validator_id={d}\n....\n", .{ vote_str, validator_id });

            // Check slot indices are within bounds
            if (source_slot >= self.justified_slots.len()) {
                return error.InvalidSlotIndex;
            }
            if (target_slot >= self.justified_slots.len()) {
                return error.InvalidSlotIndex;
            }
            if (source_slot >= self.historical_block_hashes.len()) {
                return error.InvalidSlotIndex;
            }
            if (target_slot >= self.historical_block_hashes.len()) {
                return error.InvalidSlotIndex;
            }

            // Validate vote conditions
            const is_source_justified = try self.justified_slots.get(source_slot);
            const is_target_already_justified = try self.justified_slots.get(target_slot);
            const has_correct_source_root = std.mem.eql(u8, &vote.source.root, &(try self.historical_block_hashes.get(source_slot)));
            const has_correct_target_root = std.mem.eql(u8, &vote.target.root, &(try self.historical_block_hashes.get(target_slot)));
            const target_not_ahead = target_slot <= source_slot; // Skip if target <= source (invalid)
            const is_target_justifiable = try isJustifiableSlot(self.latest_finalized.slot, target_slot);

            // Skip invalid votes
            if (!is_source_justified or
                is_target_already_justified or
                !has_correct_source_root or
                !has_correct_target_root or
                target_not_ahead or
                !is_target_justifiable)
            {
                logger.debug("skipping the vote as not viable: !(source_justified={}) or target_already_justified={} !(correct_source_root={}) or !(correct_target_root={}) or target_not_ahead={} or !(target_justifiable={})", .{
                    is_source_justified,
                    is_target_already_justified,
                    has_correct_source_root,
                    has_correct_target_root,
                    target_not_ahead,
                    is_target_justifiable,
                });
                continue;
            }

            // Validate validator ID
            if (validator_id >= num_validators) {
                return error.InvalidValidatorId;
            }

            // Get or create justification tracking for target
            var target_justifications = justifications.get(vote.target.root) orelse targetjustifications: {
                var targetjustifications = try allocator.alloc(u8, num_validators);
                for (0..targetjustifications.len) |i| {
                    targetjustifications[i] = 0;
                }
                try justifications.put(allocator, vote.target.root, targetjustifications);
                break :targetjustifications targetjustifications;
            };

            // Record this validator's vote for the target
            target_justifications[validator_id] = 1;
            try justifications.put(allocator, vote.target.root, target_justifications);

            // Count votes for this target
            var target_justifications_count: usize = 0;
            for (target_justifications) |justified| {
                if (justified == 1) {
                    target_justifications_count += 1;
                }
            }
            logger.debug("target jcount={d}: {any} justifications={any}\n", .{ target_justifications_count, vote.target.root, target_justifications });

            // Check if target has reached 2/3 majority (justification threshold)
            if (3 * target_justifications_count >= 2 * num_validators) {
                self.latest_justified = vote.target;
                try self.justified_slots.set(target_slot, true);
                _ = justifications.remove(vote.target.root);

                const justified_str_new = try self.latest_justified.toJsonString(allocator);
                defer allocator.free(justified_str_new);
                logger.debug("\n\n\n-----------------HURRAY JUSTIFICATION ------------\n{s}\n--------------\n---------------\n-------------------------\n\n\n", .{justified_str_new});

                // Check for finalization: source is finalized if target is the next valid justifiable slot
                var can_target_finalize = true;
                for (source_slot + 1..target_slot) |check_slot| {
                    if (try isJustifiableSlot(self.latest_finalized.slot, check_slot)) {
                        can_target_finalize = false;
                        break;
                    }
                }

                logger.debug("----------------can_target_finalize ({d})={any}----------\n\n", .{ source_slot, can_target_finalize });
                if (can_target_finalize == true) {
                    self.latest_finalized = vote.source;
                    const finalized_str_new = try self.latest_finalized.toJsonString(allocator);
                    defer allocator.free(finalized_str_new);
                    logger.debug("\n\n\n-----------------DOUBLE HURRAY FINALIZATION ------------\n{s}\n--------------\n---------------\n-------------------------\n\n\n", .{finalized_str_new});
                }
            }
        }

        // Update state with final justifications
        try self.withJustifications(allocator, &justifications);

        logger.debug("poststate:historical hashes={d} justified slots ={d}\n justifications_roots:{d}\n justifications_validators={d}\n", .{ self.historical_block_hashes.len(), self.justified_slots.len(), self.justifications_roots.len(), self.justifications_validators.len() });
        const justified_str_final = try self.latest_justified.toJsonString(allocator);
        defer allocator.free(justified_str_final);
        const finalized_str_final = try self.latest_finalized.toJsonString(allocator);
        defer allocator.free(finalized_str_final);
        logger.debug("poststate: justified={s} finalized={s}", .{ justified_str_final, finalized_str_final });
    }

    pub fn genGenesisState(self: *BeamState, allocator: Allocator, genesis: GenesisSpec) !void {
        var genesis_block: BeamBlock = undefined;
        try genesis_block.genGenesisBlock(allocator);
        errdefer genesis_block.deinit();

        var genesis_block_header: BeamBlockHeader = undefined;
        try genesis_block.blockToLatestBlockHeader(allocator, &genesis_block_header);

        var historical_block_hashes = try HistoricalBlockHashes.init(allocator);
        errdefer historical_block_hashes.deinit();

        var justified_slots = try JustifiedSlots.init(allocator);
        errdefer justified_slots.deinit();

        var justifications_roots = try JustificationsRoots.init(allocator);
        errdefer justifications_roots.deinit();

        var justifications_validators = try JustificationsValidators.init(allocator);
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

    pub fn genGenesisBlock(self: *const BeamState, allocator: Allocator, genesis_block: *BeamBlock) !void {
        var state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            BeamState,
            self.*,
            &state_root,
            allocator,
        );

        const attestations = try SignedVotes.init(allocator);
        errdefer attestations.deinit();

        genesis_block.* = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = ZERO_HASH,
            .state_root = state_root,
            .body = .{
                // .execution_payload_header = .{ .timestamp = 0 },
                // 3sf mini
                .attestations = attestations,
            },
        };
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

// non ssz types, difference is the variable list doesn't need upper boundaries
pub const ZkVm = enum {
    ceno,
    powdr,
    sp1,

    pub fn toJson(self: *const ZkVm, allocator: Allocator) !json.Value {
        _ = allocator; // allocator is unused, but included for API consistency
        return json.Value{ .string = @tagName(self.*) };
    }

    pub fn toJsonString(self: *const ZkVm, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BeamSTFProof = struct {
    // zk_vm: ZkVm,
    proof: []const u8,

    pub fn toJson(self: *const BeamSTFProof, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("proof", json.Value{ .string = try bytesToHex(allocator, self.proof) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamSTFProof, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const GenesisSpec = struct {
    genesis_time: u64,
    num_validators: u64,

    pub fn toJson(self: *const GenesisSpec, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("genesis_time", json.Value{ .integer = @as(i64, @intCast(self.genesis_time)) });
        try obj.put("num_validators", json.Value{ .integer = @as(i64, @intCast(self.num_validators)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const GenesisSpec, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};
pub const ChainSpec = struct {
    preset: params.Preset,
    name: []u8,

    pub fn deinit(self: *ChainSpec, allocator: Allocator) void {
        allocator.free(self.name);
    }

    pub fn toJson(self: *const ChainSpec, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("preset", json.Value{ .string = @tagName(self.preset) });
        try obj.put("name", json.Value{ .string = self.name });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const ChainSpec, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BeamSTFProverInput = struct {
    block: SignedBeamBlock,
    state: BeamState,

    pub fn toJson(self: *const BeamSTFProverInput, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("block", try self.block.toJson(allocator));
        try obj.put("state", try self.state.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamSTFProverInput, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

// some p2p containers
pub const BlockByRootRequest = struct {
    roots: ssz.utils.List(Root, params.MAX_REQUEST_BLOCKS),

    pub fn toJson(self: *const BlockByRootRequest, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        var roots_array = json.Array.init(allocator);
        for (self.roots.constSlice()) |root| {
            try roots_array.append(json.Value{ .string = try bytesToHex(allocator, &root) });
        }
        try obj.put("roots", json.Value{ .array = roots_array });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BlockByRootRequest, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

// TODO: a super hacky cloning utility for ssz container structs
// replace by a better mechanisms which could be upstreated into the ssz lib as well
pub fn sszClone(allocator: Allocator, comptime T: type, data: T) !T {
    var bytes = std.ArrayList(u8).init(allocator);
    defer bytes.deinit();

    try ssz.serialize(T, data, &bytes);
    var cloned: T = undefined;
    try ssz.deserialize(T, bytes.items[0..], &cloned, allocator);
    return cloned;
}

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "ssz seralize/deserialize signed beam block" {
    var signed_block = SignedBeamBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{
                //
                // .execution_payload_header = ExecutionPayloadHeader{ .timestamp = 23 },
                .attestations = try SignedVotes.init(std.testing.allocator),
            },
        },
        .signature = [_]u8{2} ** SIGSIZE,
    };
    defer signed_block.deinit();

    // check SignedBeamBlock serialization/deserialization
    var serialized_signed_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_signed_block.deinit();
    try ssz.serialize(SignedBeamBlock, signed_block, &serialized_signed_block);
    std.debug.print("\n\n\nserialized_signed_block ({d})", .{serialized_signed_block.items.len});

    var deserialized_signed_block: SignedBeamBlock = undefined;
    try ssz.deserialize(SignedBeamBlock, serialized_signed_block.items[0..], &deserialized_signed_block, std.testing.allocator);

    // try std.testing.expect(signed_block.message.body.execution_payload_header.timestamp == deserialized_signed_block.message.body.execution_payload_header.timestamp);
    try std.testing.expect(std.mem.eql(u8, &signed_block.message.state_root, &deserialized_signed_block.message.state_root));
    try std.testing.expect(std.mem.eql(u8, &signed_block.message.parent_root, &deserialized_signed_block.message.parent_root));

    // successful merklization
    var block_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        BeamBlock,
        signed_block.message,
        &block_root,
        std.testing.allocator,
    );
}

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

test "ssz seralize/deserialize signed stf prover input" {
    const config = BeamStateConfig{
        .num_validators = 4,
        .genesis_time = 93,
    };
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
            try validators.append(false);
            break :blk validators;
        },
        // .justifications = .{
        //     .roots = &[_]Root{},
        //     .voting_validators = &[_]u8{},
        // },
    };
    defer state.deinit();

    var block = SignedBeamBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{
                //
                // .execution_payload_header = ExecutionPayloadHeader{ .timestamp = 23 },
                .attestations = try SignedVotes.init(std.testing.allocator),
            },
        },
        .signature = [_]u8{2} ** SIGSIZE,
    };
    defer block.message.body.attestations.deinit();

    const prover_input = BeamSTFProverInput{
        .state = state,
        .block = block,
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    var serialized = std.ArrayList(u8).init(arena_allocator.allocator());
    defer serialized.deinit();
    try ssz.serialize(BeamSTFProverInput, prover_input, &serialized);

    var prover_input_deserialized: BeamSTFProverInput = undefined;
    try ssz.deserialize(BeamSTFProverInput, serialized.items[0..], &prover_input_deserialized, arena_allocator.allocator());

    // TODO create a sszEql fn in ssz to recursively compare two ssz structures
    // for now inspect two items
    try std.testing.expect(std.mem.eql(u8, &prover_input.block.signature, &prover_input_deserialized.block.signature));
    try std.testing.expect(std.mem.eql(u8, &prover_input.state.latest_block_header.state_root, &prover_input_deserialized.state.latest_block_header.state_root));
}
