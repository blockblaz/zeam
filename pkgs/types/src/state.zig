const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");
const zeam_metrics = @import("@zeam/metrics");

const block = @import("./block.zig");
const attestation = @import("./attestation.zig");
const utils = @import("./utils.zig");
const mini_3sf = @import("./mini_3sf.zig");
const validator = @import("./validator.zig");

const Allocator = std.mem.Allocator;
const AggregatedAttestations = block.AggregatedAttestations;
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
    genesis_time: u64,

    pub fn toJson(self: *const BeamStateConfig, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("genesis_time", json.Value{ .integer = @as(i64, @intCast(self.genesis_time)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamStateConfig, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer json_value.object.deinit();
        return utils.jsonToString(allocator, json_value);
    }

    pub fn freeJson(val: *json.Value, allocator: Allocator) void {
        _ = allocator;
        val.object.deinit();
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

    pub fn validatorCount(self: *const Self) usize {
        return self.validators.constSlice().len;
    }

    pub fn genGenesisState(self: *Self, allocator: Allocator, genesis: utils.GenesisSpec) !void {
        var empty_block: block.BeamBlock = undefined;
        try empty_block.setToDefault(allocator);
        defer empty_block.deinit();

        var genesis_latest_block_header: block.BeamBlockHeader = undefined;
        try empty_block.blockToLatestBlockHeader(allocator, &genesis_latest_block_header);

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

        // Populate validators from genesis pubkeys
        for (genesis.validator_pubkeys, 0..) |pubkey, i| {
            const val = validator.Validator{ .pubkey = pubkey, .index = i };
            try validators.append(val);
        }

        self.* = .{
            .config = .{
                .genesis_time = genesis.genesis_time,
            },
            .slot = 0,
            .latest_block_header = genesis_latest_block_header,
            // mini3sf
            .latest_justified = .{ .root = utils.ZERO_HASH, .slot = 0 },
            .latest_finalized = .{ .root = utils.ZERO_HASH, .slot = 0 },
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
        const num_validators = self.validatorCount();
        // Initialize justifications from state
        for (self.justifications_roots.constSlice(), 0..) |blockRoot, i| {
            if (std.mem.eql(u8, &blockRoot, &utils.ZERO_HASH)) {
                return StateTransitionError.InvalidJustificationRoot;
            }
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
            if (kv.value_ptr.*.len != self.validatorCount()) {
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

    fn fillRootToSlot(self: *const Self, allocator: Allocator, finalized_slot: Slot, root_to_slot: *std.AutoHashMapUnmanaged(Root, Slot)) !void {
        const start_slot: usize = @intCast(finalized_slot + 1);
        const historical_len_usize: usize = self.historical_block_hashes.len();
        for (start_slot..historical_len_usize) |i| {
            const root = try self.historical_block_hashes.get(i);
            const slot_i: Slot = @intCast(i);
            if (root_to_slot.getPtr(root)) |slot_ptr| {
                if (slot_i > slot_ptr.*) {
                    slot_ptr.* = slot_i;
                }
            } else {
                try root_to_slot.put(allocator, root, slot_i);
            }
        }
    }

    fn extendJustifiedSlots(self: *Self, finalized_slot: Slot, target_slot: Slot) !void {
        if (target_slot < finalized_slot) {
            return StateTransitionError.InvalidJustificationTargetSlot;
        }
        if (target_slot == finalized_slot) {
            // Genesis or the first post-finalization block has no new slots to extend.
            return;
        }
        const base: Slot = finalized_slot + 1;
        const relative_index: Slot = target_slot - base;
        const required_capacity: Slot = relative_index + 1;
        const current_len: Slot = @intCast(self.justified_slots.len());
        if (required_capacity <= current_len) {
            return StateTransitionError.InvalidJustificationCapacity;
        }
        const gap_size: Slot = required_capacity - current_len;
        const gap_size_usize: usize = @intCast(gap_size);
        for (0..gap_size_usize) |_| {
            try self.justified_slots.append(false);
        }
    }

    fn shiftJustifiedSlots(self: *Self, delta: Slot, allocator: Allocator) !void {
        if (delta == 0) {
            return;
        }
        var new_justified_slots = try JustifiedSlots.init(allocator);
        errdefer new_justified_slots.deinit();
        const old_len = self.justified_slots.len();
        var i: usize = @intCast(delta);
        while (i < old_len) : (i += 1) {
            const bit = try self.justified_slots.get(i);
            try new_justified_slots.append(bit);
        }
        self.justified_slots.deinit();
        self.justified_slots = new_justified_slots;
    }

    fn process_slot(self: *Self, allocator: Allocator) !void {

        // update state root in latest block header if its zero hash
        // i.e. just after processing the latest block of latest block header
        // this completes latest block header for parentRoot checks of new block

        if (std.mem.eql(u8, &self.latest_block_header.state_root, &utils.ZERO_HASH)) {
            var prev_state_root: [32]u8 = undefined;
            try zeam_utils.hashTreeRoot(*BeamState, self, &prev_state_root, allocator);
            self.latest_block_header.state_root = prev_state_root;
        }
    }

    pub fn process_slots(self: *Self, allocator: Allocator, slot: Slot, logger: zeam_utils.ModuleLogger) !void {
        if (slot <= self.slot) {
            logger.err("Invalid block slot={d} >= pre-state slot={d}\n", .{ slot, self.slot });
            return StateTransitionError.InvalidPreState;
        }

        const start_slot = self.slot;
        const slots_timer = zeam_metrics.lean_state_transition_slots_processing_time_seconds.start();
        defer _ = slots_timer.observe();

        while (self.slot < slot) {
            try self.process_slot(allocator);
            self.slot += 1;
        }

        if (comptime !zeam_metrics.isZKVM()) {
            const slots_processed: u64 = @intCast(slot - start_slot);
            zeam_metrics.metrics.lean_state_transition_slots_processed_total.incrBy(slots_processed);
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
        const validator_count: u64 = @intCast(self.validatorCount());
        const correct_proposer_index = staged_block.slot % validator_count;
        if (staged_block.proposer_index != correct_proposer_index) {
            logger.err("process-block-header: invalid proposer={d} slot={d} correct-proposer={d}", .{ staged_block.proposer_index, staged_block.slot, correct_proposer_index });
            return StateTransitionError.InvalidProposer;
        }

        // 4. verify latest block header is the parent
        var head_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(block.BeamBlockHeader, self.latest_block_header, &head_root, allocator);
        if (!std.mem.eql(u8, &head_root, &staged_block.parent_root)) {
            logger.err("state root={x} block root={x}\n", .{ &head_root, &staged_block.parent_root });
            return StateTransitionError.InvalidParentRoot;
        }

        // update justified and finalized with parent root in state if this is the first block post genesis
        if (self.latest_block_header.slot == 0) {
            // fixed  length array structures should just be copied over
            self.latest_justified.root = staged_block.parent_root;
            self.latest_finalized.root = staged_block.parent_root;
        }

        // extend historical block hashes structure using SSZ Lists directly
        try self.historical_block_hashes.append(staged_block.parent_root);

        const block_slot: usize = @intCast(staged_block.slot);
        const missed_slots: usize = @intCast(block_slot - self.latest_block_header.slot - 1);
        for (0..missed_slots) |i| {
            _ = i;
            try self.historical_block_hashes.append(utils.ZERO_HASH);
        }
        const last_materialized_slot: Slot = staged_block.slot - 1;
        try self.extendJustifiedSlots(self.latest_finalized.slot, last_materialized_slot);
        logger.debug("processed missed_slots={d} justified_slots_len={d} historical_block_hashes_len={d}", .{ missed_slots, self.justified_slots.len(), self.historical_block_hashes.len() });

        try staged_block.blockToLatestBlockHeader(allocator, &self.latest_block_header);
    }

    pub fn process_block(self: *Self, allocator: Allocator, staged_block: BeamBlock, logger: zeam_utils.ModuleLogger) !void {
        const block_timer = zeam_metrics.lean_state_transition_block_processing_time_seconds.start();
        defer _ = block_timer.observe();

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

    fn process_attestations(self: *Self, allocator: Allocator, attestations: AggregatedAttestations, logger: zeam_utils.ModuleLogger) !void {
        const attestations_timer = zeam_metrics.lean_state_transition_attestations_processing_time_seconds.start();
        defer _ = attestations_timer.observe();

        if (comptime !zeam_metrics.isZKVM()) {
            const attestation_count: u64 = @intCast(attestations.constSlice().len);
            zeam_metrics.metrics.lean_state_transition_attestations_processed_total.incrBy(attestation_count);
        }

        logger.debug("process attestations slot={d} \n prestate:historical hashes={d} justified slots={d} attestations={d}, ", .{ self.slot, self.historical_block_hashes.len(), self.justified_slots.len(), attestations.constSlice().len });
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
            justifications.deinit(allocator);
        }
        errdefer justifications.deinit(allocator);
        try self.getJustification(allocator, &justifications);

        var finalized_slot: Slot = self.latest_finalized.slot;

        var root_to_slot: std.AutoHashMapUnmanaged(Root, Slot) = .empty;
        defer root_to_slot.deinit(allocator);
        try self.fillRootToSlot(allocator, finalized_slot, &root_to_slot);

        // need to cast to usize for slicing ops but does this makes the STF target arch dependent?
        const num_validators: usize = @intCast(self.validatorCount());
        for (attestations.constSlice()) |aggregated_attestation| {
            var validator_indices = try attestation.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, allocator);
            defer validator_indices.deinit(allocator);

            if (validator_indices.items.len == 0) {
                continue;
            }

            const attestation_data = aggregated_attestation.data;
            // check if attestation is sane
            const source_slot: Slot = attestation_data.source.slot;
            const target_slot: Slot = attestation_data.target.slot;
            const attestation_str = try attestation_data.toJsonString(allocator);
            defer allocator.free(attestation_str);

            logger.debug("processing attestation={s} validators_count={d}\n", .{ attestation_str, validator_indices.items.len });

            const historical_len: Slot = @intCast(self.historical_block_hashes.len());
            if (source_slot >= historical_len) {
                return StateTransitionError.InvalidSlotIndex;
            }
            if (target_slot >= historical_len) {
                return StateTransitionError.InvalidSlotIndex;
            }

            const is_source_justified = try utils.isSlotJustified(finalized_slot, &self.justified_slots, source_slot);
            const is_target_already_justified = try utils.isSlotJustified(finalized_slot, &self.justified_slots, target_slot);
            const stored_source_root = try self.historical_block_hashes.get(@intCast(source_slot));
            const stored_target_root = try self.historical_block_hashes.get(@intCast(target_slot));
            const is_zero_source = std.mem.eql(u8, &attestation_data.source.root, &utils.ZERO_HASH);
            const is_zero_target = std.mem.eql(u8, &attestation_data.target.root, &utils.ZERO_HASH);
            if (is_zero_source or is_zero_target) {
                logger.debug("skipping the attestation as not viable: source_zero_root={} target_zero_root={}", .{
                    is_zero_source,
                    is_zero_target,
                });
                continue;
            }
            const has_correct_source_root = std.mem.eql(u8, &attestation_data.source.root, &stored_source_root);
            const has_correct_target_root = std.mem.eql(u8, &attestation_data.target.root, &stored_target_root);
            const has_known_root = has_correct_source_root and has_correct_target_root;
            const target_not_ahead = target_slot <= source_slot;
            const is_target_justifiable = try utils.IsJustifiableSlot(self.latest_finalized.slot, target_slot);

            if (!is_source_justified or
                // not present in 3sf mini but once a target is justified no need to run loop
                // as we remove the target from justifications map as soon as its justified
                is_target_already_justified or
                !has_known_root or
                target_not_ahead or
                !is_target_justifiable)
            {
                logger.debug("skipping the attestation as not viable: !(source_justified={}) or target_already_justified={} !(known_root={}) or target_not_ahead={} or !(target_justifiable={})", .{
                    is_source_justified,
                    is_target_already_justified,
                    has_known_root,
                    target_not_ahead,
                    is_target_justifiable,
                });
                continue;
            }

            var target_justifications = justifications.get(attestation_data.target.root) orelse targetjustifications: {
                const targetjustifications = try allocator.alloc(u8, num_validators);
                @memset(targetjustifications, 0);
                try justifications.put(allocator, attestation_data.target.root, targetjustifications);
                break :targetjustifications targetjustifications;
            };

            for (validator_indices.items) |validator_index| {
                if (validator_index >= num_validators) {
                    return StateTransitionError.InvalidValidatorId;
                }
                target_justifications[validator_index] = 1;
            }
            try justifications.put(allocator, attestation_data.target.root, target_justifications);
            var target_justifications_count: usize = 0;
            for (target_justifications) |justified| {
                if (justified == 1) {
                    target_justifications_count += 1;
                }
            }
            logger.debug("target jcount={d} target_root=0x{x} justifications_len={d}\n", .{ target_justifications_count, &attestation_data.target.root, target_justifications.len });

            // as soon as we hit the threshold do justifications
            // note that this simplification works if weight of each validator is 1
            //
            // ceilDiv is not available so this seems like a less compute intensive way without
            // requring float division, can be further optimized
            if (3 * target_justifications_count >= 2 * num_validators) {
                self.latest_justified = attestation_data.target;
                try utils.setSlotJustified(finalized_slot, &self.justified_slots, target_slot, true);
                // Free the removed justifications array before removing from map
                if (justifications.fetchRemove(attestation_data.target.root)) |kv| {
                    allocator.free(kv.value);
                }
                logger.debug(
                    "\n\n\n-----------------HURRAY JUSTIFICATION ------------\nroot=0x{x} slot={d}\n--------------\n---------------\n-------------------------\n\n\n",
                    .{ &self.latest_justified.root, self.latest_justified.slot },
                );

                // source is finalized if target is the next valid justifiable hash
                var can_target_finalize = true;
                const start_slot_usize: usize = @intCast(source_slot + 1);
                const end_slot_usize: usize = @intCast(target_slot);
                for (start_slot_usize..end_slot_usize) |slot_usize| {
                    const slot: Slot = @intCast(slot_usize);
                    if (try utils.IsJustifiableSlot(self.latest_finalized.slot, slot)) {
                        can_target_finalize = false;
                        break;
                    }
                }
                logger.debug("----------------can_target_finalize ({d})={any}----------\n\n", .{ source_slot, can_target_finalize });
                if (can_target_finalize == true) {
                    const old_finalized_slot = finalized_slot;
                    self.latest_finalized = attestation_data.source;
                    finalized_slot = self.latest_finalized.slot;

                    const delta: Slot = finalized_slot - old_finalized_slot;
                    if (delta > 0) {
                        try self.shiftJustifiedSlots(delta, allocator);

                        var roots_to_remove: std.ArrayList(Root) = .empty;
                        defer roots_to_remove.deinit(allocator);
                        var iter = justifications.iterator();
                        while (iter.next()) |entry| {
                            const slot_value = root_to_slot.get(entry.key_ptr.*) orelse return StateTransitionError.InvalidJustificationRoot;
                            if (slot_value <= finalized_slot) {
                                try roots_to_remove.append(allocator, entry.key_ptr.*);
                            }
                        }
                        for (roots_to_remove.items) |root| {
                            if (justifications.fetchRemove(root)) |kv| {
                                allocator.free(kv.value);
                            }
                        }
                    }
                    const finalized_str_new = try self.latest_finalized.toJsonString(allocator);
                    defer allocator.free(finalized_str_new);

                    logger.debug("\n\n\n-----------------DOUBLE HURRAY FINALIZATION ------------\n{s}\n--------------\n---------------\n-------------------------\n\n\n", .{finalized_str_new});
                }
            }
        }

        try self.withJustifications(allocator, &justifications);

        logger.debug("poststate:historical hashes={d} justified slots={d}\n justifications_roots:{d}\n justifications_validators={d}\n", .{ self.historical_block_hashes.len(), self.justified_slots.len(), self.justifications_roots.len(), self.justifications_validators.len() });
        const justified_str_final = try self.latest_justified.toJsonString(allocator);
        defer allocator.free(justified_str_final);
        const finalized_str_final = try self.latest_finalized.toJsonString(allocator);
        defer allocator.free(finalized_str_final);

        logger.debug("poststate: justified={s} finalized={s}", .{ justified_str_final, finalized_str_final });
    }

    pub fn genGenesisBlock(self: *const Self, allocator: Allocator, genesis_block: *block.BeamBlock) !void {
        var state_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(
            BeamState,
            self.*,
            &state_root,
            allocator,
        );

        try genesis_block.setToDefault(allocator);
        genesis_block.state_root = state_root;
    }

    pub fn genStateBlockHeader(self: *const Self, allocator: Allocator) !block.BeamBlockHeader {
        // check does it need cloning?
        var beam_block_header = self.latest_block_header;
        var state_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(
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
        var json_value = try self.toJson(allocator);
        defer self.freeJson(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    pub fn freeJson(self: *const BeamState, json_value: *json.Value, allocator: Allocator) void {
        _ = self;
        if (json_value.object.get("config")) |*config| {
            BeamStateConfig.freeJson(@constCast(config), allocator);
        }
        if (json_value.object.get("latest_block_header")) |*header| {
            BeamBlockHeader.freeJson(@constCast(header), allocator);
        }
        if (json_value.object.get("latest_justified")) |*justified| {
            Checkpoint.freeJson(@constCast(justified), allocator);
        }
        if (json_value.object.get("latest_finalized")) |*finalized| {
            Checkpoint.freeJson(@constCast(finalized), allocator);
        }
        if (json_value.object.get("historical_block_hashes")) |*hashes| {
            for (hashes.array.items) |*hash| {
                allocator.free(hash.string);
            }
            hashes.array.deinit();
        }
        if (json_value.object.get("justified_slots")) |*slots| {
            slots.array.deinit();
        }
        if (json_value.object.get("justifications_roots")) |*roots| {
            for (roots.array.items) |*root| {
                allocator.free(root.string);
            }
            roots.array.deinit();
        }
        if (json_value.object.get("justifications_validators")) |*validators_bits| {
            validators_bits.array.deinit();
        }
        if (json_value.object.get("validators")) |*validators| {
            for (validators.array.items) |*val| {
                validator.Validator.freeJson(@constCast(val), allocator);
            }
            validators.array.deinit();
        }
        json_value.object.deinit();
    }
};

test "ssz seralize/deserialize signed beam state" {
    const config = BeamStateConfig{ .genesis_time = 93 };
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

    var serialized_state: std.ArrayList(u8) = .empty;
    defer serialized_state.deinit(std.testing.allocator);
    try ssz.serialize(BeamState, state, &serialized_state, std.testing.allocator);
    std.debug.print("serialized_state ({d})\n", .{serialized_state.items.len});

    // we need to use arena allocator because deserialization allocs without providing for
    // a way to deinit, this needs to be probably addressed in ssz
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    var deserialized_state: BeamState = undefined;
    try ssz.deserialize(BeamState, serialized_state.items[0..], &deserialized_state, arena_allocator.allocator());
    try std.testing.expect(state.justifications_validators.eql(&deserialized_state.justifications_validators));

    // successful merklization
    var state_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(
        BeamState,
        state,
        &state_root,
        std.testing.allocator,
    );
}

fn makeGenesisState(allocator: Allocator, validator_count: usize) !BeamState {
    const pubkeys = try allocator.alloc(utils.Bytes52, validator_count);
    defer allocator.free(pubkeys);
    for (pubkeys, 0..) |*pk, i| {
        @memset(pk, @intCast(i + 1));
    }

    var state: BeamState = undefined;
    try state.genGenesisState(allocator, .{
        .genesis_time = 0,
        .validator_pubkeys = pubkeys,
    });
    return state;
}

fn makeAggregatedAttestation(
    allocator: Allocator,
    participant_ids: []const usize,
    attestation_slot: Slot,
    source: Checkpoint,
    target: Checkpoint,
) !attestation.AggregatedAttestation {
    var bits = try attestation.AggregationBits.init(allocator);
    errdefer bits.deinit();

    for (participant_ids) |id| {
        try attestation.aggregationBitsSet(&bits, id, true);
    }

    return .{
        .aggregation_bits = bits,
        .data = .{
            .slot = attestation_slot,
            .head = target,
            .target = target,
            .source = source,
        },
    };
}

fn makeBlock(
    allocator: Allocator,
    state: *BeamState,
    slot: Slot,
    attestations: []const attestation.AggregatedAttestation,
) !block.BeamBlock {
    var parent_root: Root = undefined;
    try zeam_utils.hashTreeRoot(block.BeamBlockHeader, state.latest_block_header, &parent_root, allocator);

    var attestations_list = try block.AggregatedAttestations.init(allocator);
    errdefer attestations_list.deinit();

    for (attestations) |att| {
        try attestations_list.append(att);
    }

    const proposer_index: u64 = slot % @as(u64, @intCast(state.validatorCount()));

    return .{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = parent_root,
        .state_root = utils.ZERO_HASH,
        .body = .{ .attestations = attestations_list },
    };
}

test "justified_slots do not include finalized boundary" {
    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(null);
    var state = try makeGenesisState(std.testing.allocator, 4);
    defer state.deinit();

    try state.process_slots(std.testing.allocator, 1, logger);
    var block_1 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{});
    defer block_1.deinit();
    try state.process_block_header(std.testing.allocator, block_1, logger);

    try std.testing.expectEqual(@as(usize, 0), state.justified_slots.len());

    try state.process_slots(std.testing.allocator, 2, logger);
    var block_2 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{});
    defer block_2.deinit();
    try state.process_block_header(std.testing.allocator, block_2, logger);

    try std.testing.expectEqual(@as(usize, 1), state.justified_slots.len());
    try std.testing.expectEqual(false, try state.justified_slots.get(0));
}

test "justified_slots rebases when finalization advances" {
    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(null);
    var state = try makeGenesisState(std.testing.allocator, 3);
    defer state.deinit();

    try state.process_slots(std.testing.allocator, 1, logger);
    var block_1 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{});
    defer block_1.deinit();
    try state.process_block(std.testing.allocator, block_1, logger);

    try state.process_slots(std.testing.allocator, 2, logger);
    var block_2_parent_root: Root = undefined;
    try zeam_utils.hashTreeRoot(block.BeamBlockHeader, state.latest_block_header, &block_2_parent_root, std.testing.allocator);

    var att_0_to_1 = try makeAggregatedAttestation(
        std.testing.allocator,
        &[_]usize{ 0, 1 },
        state.slot,
        .{ .root = block_1.parent_root, .slot = 0 },
        .{ .root = block_2_parent_root, .slot = 1 },
    );
    var att_0_to_1_transferred = false;
    defer if (!att_0_to_1_transferred) att_0_to_1.deinit();

    var block_2 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{att_0_to_1});
    att_0_to_1_transferred = true;
    defer block_2.deinit();
    try state.process_block(std.testing.allocator, block_2, logger);

    try state.process_slots(std.testing.allocator, 3, logger);
    var block_3_parent_root: Root = undefined;
    try zeam_utils.hashTreeRoot(block.BeamBlockHeader, state.latest_block_header, &block_3_parent_root, std.testing.allocator);

    var att_1_to_2 = try makeAggregatedAttestation(
        std.testing.allocator,
        &[_]usize{ 0, 1 },
        state.slot,
        .{ .root = block_2.parent_root, .slot = 1 },
        .{ .root = block_3_parent_root, .slot = 2 },
    );
    var att_1_to_2_transferred = false;
    defer if (!att_1_to_2_transferred) att_1_to_2.deinit();

    var block_3 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{att_1_to_2});
    att_1_to_2_transferred = true;
    defer block_3.deinit();
    try state.process_block(std.testing.allocator, block_3, logger);

    try std.testing.expectEqual(@as(Slot, 1), state.latest_finalized.slot);
    try std.testing.expectEqual(@as(usize, 1), state.justified_slots.len());
    try std.testing.expectEqual(true, try state.justified_slots.get(0));

    try std.testing.expect(try utils.isSlotJustified(state.latest_finalized.slot, &state.justified_slots, 1));
    try std.testing.expect(try utils.isSlotJustified(state.latest_finalized.slot, &state.justified_slots, 2));
}

test "isSlotJustified errors on out of bounds" {
    var state = try makeGenesisState(std.testing.allocator, 1);
    defer state.deinit();

    try std.testing.expectError(
        StateTransitionError.InvalidJustificationIndex,
        utils.isSlotJustified(state.latest_finalized.slot, &state.justified_slots, 1),
    );
}

test "pruning keeps pending justifications" {
    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(null);
    var state = try makeGenesisState(std.testing.allocator, 3);
    defer state.deinit();

    // Phase 1: Build a chain and justify slot 1.
    try state.process_slots(std.testing.allocator, 1, logger);
    var block_1 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{});
    defer block_1.deinit();
    try state.process_block(std.testing.allocator, block_1, logger);

    try state.process_slots(std.testing.allocator, 2, logger);
    var block_2_parent_root: Root = undefined;
    try zeam_utils.hashTreeRoot(block.BeamBlockHeader, state.latest_block_header, &block_2_parent_root, std.testing.allocator);

    var att_0_to_1 = try makeAggregatedAttestation(
        std.testing.allocator,
        &[_]usize{ 0, 1 },
        state.slot,
        .{ .root = block_1.parent_root, .slot = 0 },
        .{ .root = block_2_parent_root, .slot = 1 },
    );
    var att_0_to_1_transferred = false;
    defer if (!att_0_to_1_transferred) att_0_to_1.deinit();

    var block_2 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{att_0_to_1});
    att_0_to_1_transferred = true;
    defer block_2.deinit();
    try state.process_block(std.testing.allocator, block_2, logger);

    try std.testing.expectEqual(@as(Slot, 0), state.latest_finalized.slot);
    try std.testing.expectEqual(@as(Slot, 1), state.latest_justified.slot);

    // Phase 2: Extend chain to populate more history entries.
    try state.process_slots(std.testing.allocator, 3, logger);
    var block_3 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{});
    defer block_3.deinit();
    try state.process_block(std.testing.allocator, block_3, logger);

    try state.process_slots(std.testing.allocator, 4, logger);
    var block_4 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{});
    defer block_4.deinit();
    try state.process_block(std.testing.allocator, block_4, logger);

    try state.process_slots(std.testing.allocator, 5, logger);
    var block_5 = try makeBlock(std.testing.allocator, &state, state.slot, &[_]attestation.AggregatedAttestation{});
    defer block_5.deinit();
    try state.process_block_header(std.testing.allocator, block_5, logger);

    // Phase 3: Seed a pending justification.
    const slot_3_root = try state.historical_block_hashes.get(3);

    var pending_roots = try JustificationRoots.init(std.testing.allocator);
    errdefer pending_roots.deinit();
    try pending_roots.append(slot_3_root);

    var pending_validators = try JustificationValidators.init(std.testing.allocator);
    errdefer pending_validators.deinit();
    try pending_validators.append(true);
    try pending_validators.append(false);
    try pending_validators.append(false);

    state.justifications_roots.deinit();
    state.justifications_roots = pending_roots;
    state.justifications_validators.deinit();
    state.justifications_validators = pending_validators;

    // Phase 4: Trigger finalization to exercise pruning.
    const source_1_root = try state.historical_block_hashes.get(1);
    const slot_2_root = try state.historical_block_hashes.get(2);
    var att_1_to_2 = try makeAggregatedAttestation(
        std.testing.allocator,
        &[_]usize{ 0, 1 },
        state.slot,
        .{ .root = source_1_root, .slot = 1 },
        .{ .root = slot_2_root, .slot = 2 },
    );
    var att_1_to_2_transferred = false;
    defer if (!att_1_to_2_transferred) att_1_to_2.deinit();

    var attestations_list = try block.AggregatedAttestations.init(std.testing.allocator);
    defer {
        for (attestations_list.slice()) |*att| {
            att.deinit();
        }
        attestations_list.deinit();
    }
    try attestations_list.append(att_1_to_2);
    att_1_to_2_transferred = true;

    try state.process_attestations(std.testing.allocator, attestations_list, logger);

    try std.testing.expectEqual(@as(Slot, 1), state.latest_finalized.slot);
    try std.testing.expectEqual(@as(Slot, 2), state.latest_justified.slot);

    var found = false;
    for (state.justifications_roots.constSlice()) |root| {
        if (std.mem.eql(u8, &root, &slot_3_root)) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "encode decode state roundtrip" {
    const block_header = BeamBlockHeader{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = utils.ZERO_HASH,
        .state_root = utils.ZERO_HASH,
        .body_root = utils.ZERO_HASH,
    };

    const temp_finalized = Checkpoint{ .root = utils.ZERO_HASH, .slot = 0 };

    var state = BeamState{
        .config = BeamStateConfig{ .genesis_time = 1000 },
        .slot = 0,
        .latest_block_header = block_header,
        .latest_justified = temp_finalized,
        .latest_finalized = temp_finalized,
        .historical_block_hashes = try HistoricalBlockHashes.init(std.testing.allocator),
        .justified_slots = try JustifiedSlots.init(std.testing.allocator),
        .justifications_roots = try JustificationRoots.init(std.testing.allocator),
        .justifications_validators = try JustificationValidators.init(std.testing.allocator),
        .validators = try Validators.init(std.testing.allocator),
    };
    defer state.deinit();

    // Encode
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try ssz.serialize(BeamState, state, &encoded, std.testing.allocator);

    // Convert to hex and compare with expected value
    const expected_value = "e8030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e4000000e4000000e5000000e5000000e50000000101";
    const encoded_hex = try std.fmt.allocPrint(std.testing.allocator, "{x}", .{encoded.items});
    defer std.testing.allocator.free(encoded_hex);
    try std.testing.expectEqualStrings(expected_value, encoded_hex);

    // Decode
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    var decoded: BeamState = undefined;
    try ssz.deserialize(BeamState, encoded.items[0..], &decoded, arena_allocator.allocator());
    defer decoded.deinit();

    // Verify roundtrip
    try std.testing.expect(decoded.config.genesis_time == state.config.genesis_time);
    try std.testing.expect(decoded.slot == state.slot);
    try std.testing.expect(decoded.latest_block_header.slot == state.latest_block_header.slot);
    try std.testing.expect(decoded.latest_block_header.proposer_index == state.latest_block_header.proposer_index);
    try std.testing.expect(std.mem.eql(u8, &decoded.latest_block_header.parent_root, &state.latest_block_header.parent_root));
    try std.testing.expect(std.mem.eql(u8, &decoded.latest_block_header.state_root, &state.latest_block_header.state_root));
    try std.testing.expect(std.mem.eql(u8, &decoded.latest_block_header.body_root, &state.latest_block_header.body_root));
    try std.testing.expect(decoded.latest_justified.slot == state.latest_justified.slot);
    try std.testing.expect(std.mem.eql(u8, &decoded.latest_justified.root, &state.latest_justified.root));
    try std.testing.expect(decoded.latest_finalized.slot == state.latest_finalized.slot);
    try std.testing.expect(std.mem.eql(u8, &decoded.latest_finalized.root, &state.latest_finalized.root));
    try std.testing.expect(decoded.historical_block_hashes.len() == state.historical_block_hashes.len());
    try std.testing.expect(decoded.justified_slots.len() == state.justified_slots.len());
    try std.testing.expect(decoded.justifications_roots.len() == state.justifications_roots.len());
    try std.testing.expect(decoded.justifications_validators.len() == state.justifications_validators.len());
    try std.testing.expect(decoded.validators.len() == state.validators.len());
}

test "genesis block hash comparison" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Create first genesis state with 3 validators
    var pubkeys1 = try allocator.alloc(utils.Bytes52, 3);
    defer allocator.free(pubkeys1);
    {
        var i: usize = 0;
        while (i < pubkeys1.len) : (i += 1) {
            @memset(&pubkeys1[i], @intCast(i + 1)); // Fill with different values (1, 2, 3)
        }
    }

    const genesis_spec1 = utils.GenesisSpec{
        .genesis_time = 1000,
        .validator_pubkeys = pubkeys1,
    };

    var genesis_state1: BeamState = undefined;
    try genesis_state1.genGenesisState(allocator, genesis_spec1);
    defer genesis_state1.deinit();

    // Generate genesis block from first state
    var genesis_block1: block.BeamBlock = undefined;
    try genesis_state1.genGenesisBlock(allocator, &genesis_block1);
    defer genesis_block1.deinit();

    // Compute hash of first genesis block
    var genesis_block_hash1: Root = undefined;
    try zeam_utils.hashTreeRoot(block.BeamBlock, genesis_block1, &genesis_block_hash1, allocator);
    std.debug.print("genesis_block_hash1 =0x{x}\n", .{&genesis_block_hash1});

    // Create a second genesis state with same config but regenerated (should produce same hash)
    var genesis_state1_copy: BeamState = undefined;
    try genesis_state1_copy.genGenesisState(allocator, genesis_spec1);
    defer genesis_state1_copy.deinit();

    var genesis_block1_copy: block.BeamBlock = undefined;
    try genesis_state1_copy.genGenesisBlock(allocator, &genesis_block1_copy);
    defer genesis_block1_copy.deinit();

    var genesis_block_hash1_copy: Root = undefined;
    try zeam_utils.hashTreeRoot(block.BeamBlock, genesis_block1_copy, &genesis_block_hash1_copy, allocator);

    // Same genesis spec should produce same hash
    try std.testing.expect(std.mem.eql(u8, &genesis_block_hash1, &genesis_block_hash1_copy));

    // Create second genesis state with different validators
    var pubkeys2 = try allocator.alloc(utils.Bytes52, 3);
    defer allocator.free(pubkeys2);
    {
        var i: usize = 0;
        while (i < pubkeys2.len) : (i += 1) {
            @memset(&pubkeys2[i], @intCast(i + 10)); // Fill with different values (10, 11, 12)
        }
    }

    const genesis_spec2 = utils.GenesisSpec{
        .genesis_time = 1000, // Same genesis_time but different validators
        .validator_pubkeys = pubkeys2,
    };

    var genesis_state2: BeamState = undefined;
    try genesis_state2.genGenesisState(allocator, genesis_spec2);
    defer genesis_state2.deinit();

    var genesis_block2: block.BeamBlock = undefined;
    try genesis_state2.genGenesisBlock(allocator, &genesis_block2);
    defer genesis_block2.deinit();

    var genesis_block_hash2: Root = undefined;
    try zeam_utils.hashTreeRoot(block.BeamBlock, genesis_block2, &genesis_block_hash2, allocator);
    std.debug.print("genesis_block_hash2 =0x{x}\n", .{&genesis_block_hash2});

    // Different validators should produce different genesis block hash
    try std.testing.expect(!std.mem.eql(u8, &genesis_block_hash1, &genesis_block_hash2));

    // Create third genesis state with same validators but different genesis_time
    var pubkeys3 = try allocator.alloc(utils.Bytes52, 3);
    defer allocator.free(pubkeys3);
    {
        var i: usize = 0;
        while (i < pubkeys3.len) : (i += 1) {
            @memset(&pubkeys3[i], @intCast(i + 1)); // Same as pubkeys1
        }
    }

    const genesis_spec3 = utils.GenesisSpec{
        .genesis_time = 2000, // Different genesis_time but same validators
        .validator_pubkeys = pubkeys3,
    };

    var genesis_state3: BeamState = undefined;
    try genesis_state3.genGenesisState(allocator, genesis_spec3);
    defer genesis_state3.deinit();

    var genesis_block3: block.BeamBlock = undefined;
    try genesis_state3.genGenesisBlock(allocator, &genesis_block3);
    defer genesis_block3.deinit();

    var genesis_block_hash3: Root = undefined;
    try zeam_utils.hashTreeRoot(block.BeamBlock, genesis_block3, &genesis_block_hash3, allocator);
    std.debug.print("genesis_block_hash3 =0x{x}\n", .{&genesis_block_hash3});

    // Different genesis_time should produce different genesis block hash
    try std.testing.expect(!std.mem.eql(u8, &genesis_block_hash1, &genesis_block_hash3));

    // // Compare genesis block hashes with expected hex values
    const hash1_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{&genesis_block_hash1});
    defer allocator.free(hash1_hex);
    try std.testing.expectEqualStrings(hash1_hex, "0xcc03f11dd80dd79a4add86265fad0a141d0a553812d43b8f2c03aa43e4b002e3");

    const hash2_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{&genesis_block_hash2});
    defer allocator.free(hash2_hex);
    try std.testing.expectEqualStrings(hash2_hex, "0x6bd5347aa1397c63ed8558079fdd3042112a5f4258066e3a659a659ff75ba14f");

    const hash3_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{&genesis_block_hash3});
    defer allocator.free(hash3_hex);
    try std.testing.expectEqualStrings(hash3_hex, "0xce48a709189aa2b23b6858800996176dc13eb49c0c95d717c39e60042de1ac91");
}
