const std = @import("std");
const zeam_utils = @import("@zeam/utils");
const zeam_metrics = @import("@zeam/metrics");

const state_mod = @import("./state.zig");
const BeamState = state_mod.BeamState;
const block = @import("./block.zig");
const BeamBlock = block.BeamBlock;
const AggregatedAttestations = block.AggregatedAttestations;
const attestation = @import("./attestation.zig");
const utils = @import("./utils.zig");
const Slot = utils.Slot;
const Root = utils.Root;
const StateTransitionError = utils.StateTransitionError;
const RootToSlotCache = utils.RootToSlotCache;
const Allocator = std.mem.Allocator;

/// Wraps BeamState with logger and a justifications cache to eliminate
/// the expensive flatten/unflatten cycle on every block.
/// The cache is lazily loaded from BeamState SSZ fields and flushed
/// back before any hashTreeRoot call.
pub const CachedState = struct {
    state: *BeamState,
    allocator: Allocator,
    logger: zeam_utils.ModuleLogger,
    justifications: ?std.AutoHashMapUnmanaged(Root, []u8),

    const Self = @This();

    pub fn init(allocator: Allocator, state: *BeamState, logger: zeam_utils.ModuleLogger) Self {
        return .{
            .state = state,
            .allocator = allocator,
            .logger = logger,
            .justifications = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.justifications) |*justifications| {
            var iterator = justifications.iterator();
            while (iterator.next()) |entry| {
                self.allocator.free(entry.value_ptr.*);
            }
            justifications.deinit(self.allocator);
            self.justifications = null;
        }
    }

    /// Lazily loads the justifications map from BeamState SSZ fields.
    /// Returns a pointer to the cached map for direct mutation.
    pub fn ensureJustificationsLoaded(self: *Self) !*std.AutoHashMapUnmanaged(Root, []u8) {
        if (self.justifications == null) {
            self.justifications = .empty;
            try self.state.getJustification(self.allocator, &self.justifications.?);
        }
        return &self.justifications.?;
    }

    /// Writes the cached justifications back to the BeamState SSZ fields,
    /// then frees and nulls the cache.
    pub fn flushJustifications(self: *Self) !void {
        if (self.justifications) |*justifications| {
            try self.state.withJustifications(self.allocator, justifications);
            var iterator = justifications.iterator();
            while (iterator.next()) |entry| {
                self.allocator.free(entry.value_ptr.*);
            }
            justifications.deinit(self.allocator);
            self.justifications = null;
        }
    }

    /// Flush before delegating to process_slots, which calls hashTreeRoot internally.
    pub fn process_slots(self: *Self, slot: Slot) !void {
        try self.flushJustifications();
        try self.state.process_slots(self.allocator, slot, self.logger);
    }

    pub fn process_block(self: *Self, staged_block: BeamBlock, cache: ?*RootToSlotCache) !void {
        const block_timer = zeam_metrics.lean_state_transition_block_processing_time_seconds.start();
        defer _ = block_timer.observe();

        try self.state.process_block_header(self.allocator, staged_block, self.logger);
        try self.process_attestations(staged_block.body.attestations, cache);
    }

    fn process_attestations(self: *Self, attestations: AggregatedAttestations, cache: ?*RootToSlotCache) !void {
        const allocator = self.allocator;
        const logger = self.logger;

        const attestations_timer = zeam_metrics.lean_state_transition_attestations_processing_time_seconds.start();
        defer _ = attestations_timer.observe();

        if (comptime !zeam_metrics.isZKVM()) {
            const attestation_count: u64 = @intCast(attestations.constSlice().len);
            zeam_metrics.metrics.lean_state_transition_attestations_processed_total.incrBy(attestation_count);
        }

        logger.debug("process attestations slot={d} \n prestate:historical hashes={d} justified slots={d} attestations={d}, ", .{ self.state.slot, self.state.historical_block_hashes.len(), self.state.justified_slots.len(), attestations.constSlice().len });
        const justified_str = try self.state.latest_justified.toJsonString(allocator);
        defer allocator.free(justified_str);
        const finalized_str = try self.state.latest_finalized.toJsonString(allocator);
        defer allocator.free(finalized_str);

        logger.debug("prestate justified={s} finalized={s}", .{ justified_str, finalized_str });

        const justifications = try self.ensureJustificationsLoaded();

        var finalized_slot: Slot = self.state.latest_finalized.slot;

        // Use the global cache directly if provided, otherwise build a local cache.
        var owned_cache: ?RootToSlotCache = if (cache == null) RootToSlotCache.init(allocator) else null;
        defer if (owned_cache) |*oc| oc.deinit();
        const block_cache = cache orelse &(owned_cache.?);
        if (owned_cache != null) {
            try self.state.initRootToSlotCache(block_cache);
        }

        const num_validators: usize = @intCast(self.state.validatorCount());
        for (attestations.constSlice()) |aggregated_attestation| {
            var validator_indices = try attestation.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, allocator);
            defer validator_indices.deinit(allocator);

            if (validator_indices.items.len == 0) {
                continue;
            }

            const attestation_data = aggregated_attestation.data;
            const source_slot: Slot = attestation_data.source.slot;
            const target_slot: Slot = attestation_data.target.slot;
            const attestation_str = try attestation_data.toJsonString(allocator);
            defer allocator.free(attestation_str);

            logger.debug("processing attestation={s} validators_count={d}\n", .{ attestation_str, validator_indices.items.len });

            const historical_len: Slot = @intCast(self.state.historical_block_hashes.len());
            if (source_slot >= historical_len) {
                return StateTransitionError.InvalidSlotIndex;
            }
            if (target_slot >= historical_len) {
                return StateTransitionError.InvalidSlotIndex;
            }

            const is_source_justified = try utils.isSlotJustified(finalized_slot, &self.state.justified_slots, source_slot);
            const is_target_already_justified = try utils.isSlotJustified(finalized_slot, &self.state.justified_slots, target_slot);
            const stored_source_root = try self.state.historical_block_hashes.get(@intCast(source_slot));
            const stored_target_root = try self.state.historical_block_hashes.get(@intCast(target_slot));
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
            const is_target_justifiable = try utils.IsJustifiableSlot(self.state.latest_finalized.slot, target_slot);

            if (!is_source_justified or
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

            if (3 * target_justifications_count >= 2 * num_validators) {
                self.state.latest_justified = attestation_data.target;
                try utils.setSlotJustified(finalized_slot, &self.state.justified_slots, target_slot, true);
                if (justifications.fetchRemove(attestation_data.target.root)) |kv| {
                    allocator.free(kv.value);
                }
                logger.debug("justified root=0x{x} slot={d}", .{ &self.state.latest_justified.root, self.state.latest_justified.slot });

                var can_target_finalize = true;
                const start_slot_usize: usize = @intCast(source_slot + 1);
                const end_slot_usize: usize = @intCast(target_slot);
                for (start_slot_usize..end_slot_usize) |slot_usize| {
                    const slot: Slot = @intCast(slot_usize);
                    if (try utils.IsJustifiableSlot(self.state.latest_finalized.slot, slot)) {
                        can_target_finalize = false;
                        break;
                    }
                }
                logger.debug("----------------can_target_finalize ({d})={any}----------\n\n", .{ source_slot, can_target_finalize });
                if (can_target_finalize == true) {
                    const old_finalized_slot = finalized_slot;
                    self.state.latest_finalized = attestation_data.source;
                    finalized_slot = self.state.latest_finalized.slot;

                    const delta: Slot = finalized_slot - old_finalized_slot;
                    if (delta > 0) {
                        try self.state.shiftJustifiedSlots(delta, allocator);

                        var roots_to_remove: std.ArrayList(Root) = .empty;
                        defer roots_to_remove.deinit(allocator);
                        var iter = justifications.iterator();
                        while (iter.next()) |entry| {
                            const root = entry.key_ptr.*;
                            const slot = block_cache.get(root) orelse return StateTransitionError.InvalidJustificationRoot;
                            if (slot <= finalized_slot) {
                                try roots_to_remove.append(allocator, root);
                            }
                        }
                        for (roots_to_remove.items) |root| {
                            if (justifications.fetchRemove(root)) |kv| {
                                allocator.free(kv.value);
                            }
                        }
                    }
                    const finalized_str_new = try self.state.latest_finalized.toJsonString(allocator);
                    defer allocator.free(finalized_str_new);

                    logger.debug("finalized={s}", .{finalized_str_new});
                }
            }
        }

        logger.debug("poststate:historical hashes={d} justified slots={d}\n justifications_roots:{d}\n justifications_validators={d}\n", .{ self.state.historical_block_hashes.len(), self.state.justified_slots.len(), self.state.justifications_roots.len(), self.state.justifications_validators.len() });
        const justified_str_final = try self.state.latest_justified.toJsonString(allocator);
        defer allocator.free(justified_str_final);
        const finalized_str_final = try self.state.latest_finalized.toJsonString(allocator);
        defer allocator.free(finalized_str_final);

        logger.debug("poststate: justified={s} finalized={s}", .{ justified_str_final, finalized_str_final });
    }
};
