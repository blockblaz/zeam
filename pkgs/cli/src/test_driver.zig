/// Fork-choice test driver for hive lean-spec-tests.
///
/// Implements:
///   POST /lean/v0/test_driver/fork_choice/init
///   POST /lean/v0/test_driver/fork_choice/step
///
/// Logic mirrors pkgs/spectest/src/runner/fork_choice_runner.zig but adapted
/// for persistent per-request state and HTTP responses.
const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;
const JsonValue = std.json.Value;

const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const zeam_utils = @import("@zeam/utils");
const node = @import("@zeam/node");
const forkchoice = node.fcFactory;
const state_transition = @import("@zeam/state-transition");
const node_constants = node.constants;
const params = @import("@zeam/params");

pub const read_max_bytes: usize = 16 * 1024 * 1024;

const INTERVALS_PER_SLOT = node_constants.INTERVALS_PER_SLOT;

const StateMap = std.AutoHashMapUnmanaged(types.Root, *types.BeamState);
const StateList = std.ArrayListUnmanaged(*types.BeamState);
const LabelMap = std.StringHashMapUnmanaged(types.Root);

const BlockAttestationSummary = struct {
    participants: []u64,
    attestation_slot: u64,
    target_slot: u64,
};
const BlockAttestationList = std.ArrayListUnmanaged(BlockAttestationSummary);

/// Persistent fork-choice state for the hive test driver.
/// Must be kept at a stable heap address (use as *ForkChoiceDriverState).
pub const ForkChoiceDriverState = struct {
    allocator: Allocator,
    fork_choice: forkchoice.ForkChoice,
    anchor_state_ptr: *types.BeamState,
    state_map: StateMap,
    allocated_states: StateList,
    label_map: LabelMap,
    block_attestations: BlockAttestationList,
    chain_config: configs.ChainConfig,

    pub fn deinit(self: *@This()) void {
        self.fork_choice.deinit();
        for (self.allocated_states.items) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
        self.allocated_states.deinit(self.allocator);
        self.state_map.deinit(self.allocator);
        self.label_map.deinit(self.allocator);
        for (self.block_attestations.items) |entry| {
            self.allocator.free(entry.participants);
        }
        self.block_attestations.deinit(self.allocator);
        // anchor_state_ptr is NOT in allocated_states; free separately
        self.anchor_state_ptr.deinit();
        self.allocator.destroy(self.anchor_state_ptr);
        self.chain_config.deinit(self.allocator);
    }
};

// ---------------------------------------------------------------------------
// JSON parsing helpers (simplified from spectest json_expect.zig)
// ---------------------------------------------------------------------------

fn parseBytesValue(comptime T: type, value: JsonValue) !T {
    comptime {
        const info = @typeInfo(T);
        if (info != .array or info.array.child != u8)
            @compileError("parseBytesValue requires an array-of-u8 type");
    }
    const s = switch (value) {
        .string => |str| str,
        else => return error.InvalidField,
    };
    const body = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    const expected_len = comptime (@typeInfo(T).array.len * 2);
    if (body.len != expected_len) return error.InvalidField;
    var out: T = undefined;
    _ = std.fmt.hexToBytes(&out, body) catch return error.InvalidField;
    return out;
}

fn parseRootValue(value: JsonValue) !types.Root {
    return parseBytesValue(types.Root, value);
}

fn parseU64Value(value: JsonValue) !u64 {
    return switch (value) {
        .integer => |n| if (n >= 0) @as(u64, @intCast(n)) else error.InvalidField,
        else => error.InvalidField,
    };
}

fn parseStringValue(value: JsonValue) ![]const u8 {
    return switch (value) {
        .string => |s| s,
        else => error.InvalidField,
    };
}

fn parseBoolValue(value: JsonValue) !bool {
    return switch (value) {
        .bool => |b| b,
        else => error.InvalidField,
    };
}

fn requireObject(value: JsonValue) !std.json.ObjectMap {
    return switch (value) {
        .object => |m| m,
        else => error.InvalidField,
    };
}

fn getFieldMulti(obj: std.json.ObjectMap, names: []const []const u8) ?JsonValue {
    for (names) |name| {
        if (obj.get(name)) |v| return v;
    }
    return null;
}

fn requireField(obj: std.json.ObjectMap, names: []const []const u8) !JsonValue {
    return getFieldMulti(obj, names) orelse error.MissingField;
}

fn parseU64Field(obj: std.json.ObjectMap, names: []const []const u8) !u64 {
    return parseU64Value(try requireField(obj, names));
}

fn parseRootField(obj: std.json.ObjectMap, names: []const []const u8) !types.Root {
    return parseRootValue(try requireField(obj, names));
}

fn parseBytesField(comptime T: type, obj: std.json.ObjectMap, names: []const []const u8) !T {
    return parseBytesValue(T, try requireField(obj, names));
}

fn parseObjectField(obj: std.json.ObjectMap, names: []const []const u8) !std.json.ObjectMap {
    return requireObject(try requireField(obj, names));
}

fn parseStringField(obj: std.json.ObjectMap, names: []const []const u8) ![]const u8 {
    return parseStringValue(try requireField(obj, names));
}

fn appendRootsDataField(list: anytype, value: JsonValue) !void {
    const obj = try requireObject(value);
    const data_val = obj.get("data") orelse return;
    const arr = switch (data_val) {
        .array => |a| a,
        else => return error.InvalidField,
    };
    for (arr.items) |item| {
        const root = try parseRootValue(item);
        list.append(root) catch return error.InvalidField;
    }
}

fn appendBoolsDataField(list: anytype, value: JsonValue) !void {
    const obj = try requireObject(value);
    const data_val = obj.get("data") orelse return;
    const arr = switch (data_val) {
        .array => |a| a,
        else => return error.InvalidField,
    };
    for (arr.items) |item| {
        const b = switch (item) {
            .bool => |v| v,
            else => return error.InvalidField,
        };
        list.append(b) catch return error.InvalidField;
    }
}

// ---------------------------------------------------------------------------
// State / block parsing (mirrors fork_choice_runner.zig buildState/buildBlock)
// ---------------------------------------------------------------------------

fn parseCheckpointField(obj: std.json.ObjectMap, field: []const u8) !types.Checkpoint {
    const cp_obj = try parseObjectField(obj, &.{field});
    return types.Checkpoint{
        .root = try parseRootField(cp_obj, &.{"root"}),
        .slot = try parseU64Field(cp_obj, &.{"slot"}),
    };
}

fn parseBlockHeaderObj(obj: std.json.ObjectMap) !types.BeamBlockHeader {
    return types.BeamBlockHeader{
        .slot = try parseU64Field(obj, &.{"slot"}),
        .proposer_index = try parseU64Field(obj, &.{ "proposerIndex", "proposer_index" }),
        .parent_root = try parseRootField(obj, &.{ "parentRoot", "parent_root" }),
        .state_root = try parseRootField(obj, &.{ "stateRoot", "state_root" }),
        .body_root = try parseRootField(obj, &.{ "bodyRoot", "body_root" }),
    };
}

pub fn buildStateFromJson(allocator: Allocator, value: JsonValue) !types.BeamState {
    const obj = try requireObject(value);

    const config_obj = try parseObjectField(obj, &.{"config"});
    const genesis_time = try parseU64Field(config_obj, &.{"genesisTime"});
    const slot = try parseU64Field(obj, &.{"slot"});

    const header_obj = try parseObjectField(obj, &.{"latestBlockHeader"});
    const latest_block_header = try parseBlockHeaderObj(header_obj);

    const latest_justified = try parseCheckpointField(obj, "latestJustified");
    const latest_finalized = try parseCheckpointField(obj, "latestFinalized");

    var historical = try types.HistoricalBlockHashes.init(allocator);
    errdefer historical.deinit();
    if (obj.get("historicalBlockHashes")) |v| {
        try appendRootsDataField(&historical, v);
    }

    var justified_slots = try types.JustifiedSlots.init(allocator);
    errdefer justified_slots.deinit();
    if (obj.get("justifiedSlots")) |v| {
        try appendBoolsDataField(&justified_slots, v);
    }

    var validators = try types.Validators.init(allocator);
    errdefer validators.deinit();
    if (obj.get("validators")) |val| {
        const validators_obj = try requireObject(val);
        if (validators_obj.get("data")) |data_val| {
            const arr = switch (data_val) {
                .array => |a| a,
                else => return error.InvalidField,
            };
            for (arr.items, 0..) |item, idx| {
                const vobj = try requireObject(item);
                const att_pubkey = try parseBytesField(types.Bytes52, vobj, &.{"attestationPubkey"});
                const prop_pubkey = try parseBytesField(types.Bytes52, vobj, &.{"proposalPubkey"});
                const validator_index: u64 = if (vobj.get("index")) |iv| try parseU64Value(iv) else @intCast(idx);
                validators.append(.{
                    .attestation_pubkey = att_pubkey,
                    .proposal_pubkey = prop_pubkey,
                    .index = validator_index,
                }) catch return error.InvalidField;
            }
        }
    }

    var just_roots = try types.JustificationRoots.init(allocator);
    errdefer just_roots.deinit();
    if (obj.get("justificationsRoots")) |v| {
        try appendRootsDataField(&just_roots, v);
    }

    var just_validators = try types.JustificationValidators.init(allocator);
    errdefer just_validators.deinit();
    if (obj.get("justificationsValidators")) |v| {
        try appendBoolsDataField(&just_validators, v);
    }

    return types.BeamState{
        .config = .{ .genesis_time = genesis_time },
        .slot = slot,
        .latest_block_header = latest_block_header,
        .latest_justified = latest_justified,
        .latest_finalized = latest_finalized,
        .historical_block_hashes = historical,
        .justified_slots = justified_slots,
        .validators = validators,
        .justifications_roots = just_roots,
        .justifications_validators = just_validators,
    };
}

fn parseAttestationsFromJson(
    allocator: Allocator,
    value: JsonValue,
) !types.AggregatedAttestations {
    switch (value) {
        .null => return types.AggregatedAttestations.init(allocator) catch return error.InvalidField,
        .object => |obj| {
            const data_value = obj.get("data") orelse {
                return types.AggregatedAttestations.init(allocator) catch return error.InvalidField;
            };
            const arr = switch (data_value) {
                .array => |a| a,
                else => return error.InvalidField,
            };

            var agg_atts = types.AggregatedAttestations.init(allocator) catch return error.InvalidField;
            errdefer agg_atts.deinit();

            for (arr.items) |item| {
                const att_obj = try requireObject(item);

                const bits_value = att_obj.get("aggregationBits") orelse return error.MissingField;
                const bits_obj = try requireObject(bits_value);
                const bits_data = bits_obj.get("data") orelse return error.MissingField;
                const bits_arr = switch (bits_data) {
                    .array => |a| a,
                    else => return error.InvalidField,
                };

                var aggregation_bits = types.AggregationBits.init(allocator) catch return error.InvalidField;
                errdefer aggregation_bits.deinit();
                for (bits_arr.items) |bit_val| {
                    const b = try parseBoolValue(bit_val);
                    aggregation_bits.append(b) catch return error.InvalidField;
                }

                const data_obj = try parseObjectField(att_obj, &.{"data"});
                const att_slot = try parseU64Field(data_obj, &.{"slot"});
                const head_obj = try parseObjectField(data_obj, &.{"head"});
                const target_obj = try parseObjectField(data_obj, &.{"target"});
                const source_obj = try parseObjectField(data_obj, &.{"source"});

                const agg_att = types.AggregatedAttestation{
                    .aggregation_bits = aggregation_bits,
                    .data = .{
                        .slot = att_slot,
                        .head = .{
                            .root = try parseRootField(head_obj, &.{"root"}),
                            .slot = try parseU64Field(head_obj, &.{"slot"}),
                        },
                        .target = .{
                            .root = try parseRootField(target_obj, &.{"root"}),
                            .slot = try parseU64Field(target_obj, &.{"slot"}),
                        },
                        .source = .{
                            .root = try parseRootField(source_obj, &.{"root"}),
                            .slot = try parseU64Field(source_obj, &.{"slot"}),
                        },
                    },
                };

                agg_atts.append(agg_att) catch return error.InvalidField;
            }

            return agg_atts;
        },
        else => return error.InvalidField,
    }
}

fn buildBlockFromJson(
    allocator: Allocator,
    value: JsonValue,
) !types.BeamBlock {
    const obj = try requireObject(value);

    const slot = try parseU64Field(obj, &.{"slot"});
    const proposer_index = try parseU64Field(obj, &.{ "proposerIndex", "proposer_index" });
    const parent_root = try parseRootField(obj, &.{ "parentRoot", "parent_root" });
    const state_root = try parseRootField(obj, &.{ "stateRoot", "state_root" });

    const body_obj = try parseObjectField(obj, &.{"body"});
    const attestations_val = body_obj.get("attestations") orelse JsonValue{ .null = {} };
    const att_list = try parseAttestationsFromJson(allocator, attestations_val);

    return types.BeamBlock{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = parent_root,
        .state_root = state_root,
        .body = .{ .attestations = att_list },
    };
}

/// Mirrors fork_choice_runner.zig buildChainConfig.
fn buildChainConfig(allocator: Allocator, state: *types.BeamState) !configs.ChainConfig {
    const chain_spec =
        \\{"preset":"mainnet","name":"devnet0","fork_digest":"00000000"}
    ;
    const parse_options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    var parse_result = json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, parse_options) catch
        return error.InvalidState;
    defer parse_result.deinit();
    var chain_options = parse_result.value;
    chain_options.genesis_time = state.config.genesis_time;

    const validators_slice = state.validators.constSlice();
    const num_validators = validators_slice.len;
    const att_pubkeys = try allocator.alloc(types.Bytes52, num_validators);
    errdefer allocator.free(att_pubkeys);
    const prop_pubkeys = try allocator.alloc(types.Bytes52, num_validators);
    errdefer allocator.free(prop_pubkeys);
    for (validators_slice, 0..) |vi, idx| {
        att_pubkeys[idx] = vi.attestation_pubkey;
        prop_pubkeys[idx] = vi.proposal_pubkey;
    }
    chain_options.validator_attestation_pubkeys = att_pubkeys;
    chain_options.validator_proposal_pubkeys = prop_pubkeys;

    return configs.ChainConfig.init(configs.Chain.custom, chain_options) catch
        return error.InvalidState;
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Initialize a new ForkChoiceDriverState from an init request body.
/// The driver is heap-allocated; caller owns it (call deinit + destroy when done).
/// `logger` must outlive the returned state.
pub fn initForkChoiceDriver(
    driver_allocator: Allocator,
    logger: zeam_utils.ModuleLogger,
    body_json: JsonValue,
) !*ForkChoiceDriverState {
    const body_obj = try requireObject(body_json);

    const anchor_state_value = body_obj.get("anchorState") orelse return error.MissingField;
    const anchor_block_value = body_obj.get("anchorBlock") orelse return error.MissingField;

    // Parse into temporaries (arena memory is fine; we copy what we need)
    var anchor_state_temp = try buildStateFromJson(driver_allocator, anchor_state_value);
    // Don't defer deinit here — will be moved to heap below
    errdefer anchor_state_temp.deinit();

    var anchor_block = try buildBlockFromJson(driver_allocator, anchor_block_value);
    defer anchor_block.deinit();

    // Validate anchor: anchorBlock.state_root must == hash_tree_root(anchorState)
    var expected_state_root: types.Root = undefined;
    zeam_utils.hashTreeRoot(types.BeamState, anchor_state_temp, &expected_state_root, driver_allocator) catch
        return error.HashFailed;
    if (!std.mem.eql(u8, &anchor_block.state_root, &expected_state_root)) {
        return error.AnchorMismatch;
    }

    // Build chain config (uses driver_allocator for pubkey slices)
    var chain_config = try buildChainConfig(driver_allocator, &anchor_state_temp);
    errdefer chain_config.deinit(driver_allocator);

    // Move anchor state to a stable heap address
    const anchor_state_ptr = try driver_allocator.create(types.BeamState);
    anchor_state_ptr.* = anchor_state_temp;
    // anchor_state_temp is now "moved" — clear its errdefer by disabling it
    // (we rely on anchor_state_ptr's errdefer from here on)
    errdefer {
        anchor_state_ptr.deinit();
        driver_allocator.destroy(anchor_state_ptr);
    }
    // Prevent double-deinit: clear fields so the stack copy's deinit is a no-op.
    // We set anchor_state_temp to a zeroed-out state so its errdefer (if somehow triggered)
    // won't double-free. Actually the errdefer above fires on the *ptr; the local temp's
    // errdefer was already set before the move. We just need to neutralise it.
    // The cleanest approach: after successful move, null out the moved-from
    // local so its deinit is safe. We'll just let Zig's errdefer chain handle it.
    // Since anchor_state_temp.deinit() would free its internal lists and we've done a
    // bitwise copy, calling deinit on both would double-free. To prevent this, we
    // reassign anchor_state_temp to a fresh empty state:
    anchor_state_temp = types.BeamState{
        .config = .{ .genesis_time = 0 },
        .slot = 0,
        .latest_block_header = std.mem.zeroes(types.BeamBlockHeader),
        .latest_justified = std.mem.zeroes(types.Checkpoint),
        .latest_finalized = std.mem.zeroes(types.Checkpoint),
        .historical_block_hashes = try types.HistoricalBlockHashes.init(driver_allocator),
        .justified_slots = try types.JustifiedSlots.init(driver_allocator),
        .validators = try types.Validators.init(driver_allocator),
        .justifications_roots = try types.JustificationRoots.init(driver_allocator),
        .justifications_validators = try types.JustificationValidators.init(driver_allocator),
    };

    // Compute anchor block root for state_map
    var anchor_block_root: types.Root = undefined;
    zeam_utils.hashTreeRoot(types.BeamBlock, anchor_block, &anchor_block_root, driver_allocator) catch
        return error.HashFailed;

    // Init fork choice (uses anchor_state_ptr for anchorState)
    var fork_choice = try forkchoice.ForkChoice.init(driver_allocator, .{
        .config = chain_config,
        .anchorState = anchor_state_ptr,
        .logger = logger,
    });
    errdefer fork_choice.deinit();

    // Set up state map
    var state_map = StateMap.empty;
    errdefer state_map.deinit(driver_allocator);
    try state_map.put(driver_allocator, anchor_block_root, anchor_state_ptr);

    var allocated_states = StateList.empty;
    errdefer allocated_states.deinit(driver_allocator);

    var label_map = LabelMap.empty;
    errdefer label_map.deinit(driver_allocator);
    try label_map.put(driver_allocator, "genesis", anchor_block_root);

    const block_attestations = BlockAttestationList.empty;
    // (deinit is a no-op when empty)

    // Heap-allocate the driver state so it can be stored at a stable address
    const driver = try driver_allocator.create(ForkChoiceDriverState);
    driver.* = .{
        .allocator = driver_allocator,
        .fork_choice = fork_choice,
        .anchor_state_ptr = anchor_state_ptr,
        .state_map = state_map,
        .allocated_states = allocated_states,
        .label_map = label_map,
        .block_attestations = block_attestations,
        .chain_config = chain_config,
    };
    return driver;
}

// ---------------------------------------------------------------------------
// Step execution helpers
// ---------------------------------------------------------------------------

fn advanceForkchoiceIntervals(driver: *ForkChoiceDriverState, target_intervals: u64, has_proposal: bool) !void {
    while (driver.fork_choice.fcStore.slot_clock.time.load(.monotonic) < target_intervals) {
        const next_interval: u64 = driver.fork_choice.fcStore.slot_clock.time.load(.monotonic) + 1;
        const signal_proposal = has_proposal and next_interval == target_intervals;
        try driver.fork_choice.onInterval(next_interval, signal_proposal);
    }
}

fn slotToIntervals(slot: u64) u64 {
    return slot * INTERVALS_PER_SLOT;
}

fn timeToIntervals(genesis_time: u64, time_value: u64) u64 {
    const delta = time_value - genesis_time;
    const intervals_per_slot: u64 = INTERVALS_PER_SLOT;
    const numerator = std.math.mulWide(u64, delta, intervals_per_slot);
    const quotient = numerator / params.SECONDS_PER_SLOT;
    return @intCast(quotient);
}

fn clearBlockAttestations(allocator: Allocator, list: *BlockAttestationList) void {
    for (list.items) |entry| {
        allocator.free(entry.participants);
    }
    list.clearRetainingCapacity();
}

fn processBlockStep(
    driver: *ForkChoiceDriverState,
    step_obj: std.json.ObjectMap,
) !void {
    const block_wrapper = step_obj.get("block") orelse return error.MissingField;

    const block_wrapper_obj: ?std.json.ObjectMap = switch (block_wrapper) {
        .object => |m| m,
        else => null,
    };

    const block_value = blk: {
        if (block_wrapper_obj) |wo| {
            if (wo.get("block")) |nested| break :blk nested;
        }
        break :blk block_wrapper;
    };

    var block = try buildBlockFromJson(driver.allocator, block_value);
    defer block.deinit();

    // Capture aggregated attestations for block-level checks
    clearBlockAttestations(driver.allocator, &driver.block_attestations);
    const aggregated_attestations = block.body.attestations.constSlice();
    driver.block_attestations.ensureTotalCapacity(driver.allocator, aggregated_attestations.len) catch
        return error.OutOfMemory;
    for (aggregated_attestations) |agg_att| {
        var indices = types.aggregationBitsToValidatorIndices(&agg_att.aggregation_bits, driver.allocator) catch
            return error.InvalidField;
        defer indices.deinit(driver.allocator);

        const participants = try driver.allocator.alloc(u64, indices.items.len);
        errdefer driver.allocator.free(participants);
        for (indices.items, 0..) |vi, i| {
            participants[i] = @intCast(vi);
        }
        std.sort.heap(u64, participants, {}, std.sort.asc(u64));
        driver.block_attestations.appendAssumeCapacity(.{
            .participants = participants,
            .attestation_slot = agg_att.data.slot,
            .target_slot = agg_att.data.target.slot,
        });
    }

    var block_root: types.Root = undefined;
    zeam_utils.hashTreeRoot(types.BeamBlock, block, &block_root, driver.allocator) catch
        return error.HashFailed;

    const parent_state_ptr = driver.state_map.get(block.parent_root) orelse
        return error.UnknownParent;

    const target_intervals = slotToIntervals(block.slot);
    try advanceForkchoiceIntervals(driver, target_intervals, true);

    const new_state_ptr = try driver.allocator.create(types.BeamState);
    errdefer {
        new_state_ptr.deinit();
        driver.allocator.destroy(new_state_ptr);
    }
    try types.sszClone(driver.allocator, types.BeamState, parent_state_ptr.*, new_state_ptr);

    state_transition.apply_transition(driver.allocator, new_state_ptr, block, .{
        .logger = driver.fork_choice.logger,
        .validateResult = false,
    }) catch return error.StateTransitionFailed;

    _ = driver.fork_choice.onBlock(block, new_state_ptr, .{
        .currentSlot = block.slot,
        .blockDelayMs = 0,
        .blockRoot = block_root,
        .confirmed = true,
    }) catch return error.OnBlockFailed;

    try driver.state_map.put(driver.allocator, block_root, new_state_ptr);
    try driver.allocated_states.append(driver.allocator, new_state_ptr);

    // Store block body attestations as known aggregated payloads
    for (aggregated_attestations) |agg_att| {
        var proof_template = types.AggregatedSignatureProof.init(driver.allocator) catch continue;
        defer proof_template.deinit();

        const bits_len = agg_att.aggregation_bits.len();
        for (0..bits_len) |i| {
            if (agg_att.aggregation_bits.get(i) catch false) {
                types.aggregationBitsSet(&proof_template.participants, i, true) catch continue;
            }
        }

        driver.fork_choice.storeAggregatedPayload(&agg_att.data, proof_template, true) catch {};

        // Register individual attestations in the fork-choice tracker
        var indices2 = types.aggregationBitsToValidatorIndices(&agg_att.aggregation_bits, driver.allocator) catch continue;
        defer indices2.deinit(driver.allocator);
        for (indices2.items) |vi| {
            const att = types.Attestation{
                .validator_id = @intCast(vi),
                .data = agg_att.data,
            };
            driver.fork_choice.onAttestation(att, true) catch continue;
        }
    }

    _ = try driver.fork_choice.updateHead();

    // Track blockRootLabel if provided
    if (block_wrapper_obj) |wo| {
        if (wo.get("blockRootLabel")) |label_value| {
            const label = try parseStringValue(label_value);
            try driver.label_map.put(driver.allocator, label, block_root);
        }
    }
}

fn processTickStep(
    driver: *ForkChoiceDriverState,
    step_obj: std.json.ObjectMap,
) !void {
    const time_value = try parseU64Field(step_obj, &.{"time"});
    const anchor_genesis_time = driver.fork_choice.anchorState.config.genesis_time;
    if (time_value < anchor_genesis_time) return error.TickBeforeGenesis;
    const target_intervals = timeToIntervals(anchor_genesis_time, time_value);
    try advanceForkchoiceIntervals(driver, target_intervals, false);
}

fn processAttestationStep(
    driver: *ForkChoiceDriverState,
    step_obj: std.json.ObjectMap,
) !void {
    const att_value = step_obj.get("attestation") orelse return error.MissingField;
    const att_obj = try requireObject(att_value);

    // Parse as aggregated attestation (same format as block body attestations)
    const bits_value = att_obj.get("aggregationBits") orelse return error.MissingField;
    const bits_obj = try requireObject(bits_value);
    const bits_data = bits_obj.get("data") orelse return error.MissingField;
    const bits_arr = switch (bits_data) {
        .array => |a| a,
        else => return error.InvalidField,
    };

    var aggregation_bits = types.AggregationBits.init(driver.allocator) catch return error.OutOfMemory;
    defer aggregation_bits.deinit();
    for (bits_arr.items) |bit_val| {
        const b = try parseBoolValue(bit_val);
        aggregation_bits.append(b) catch return error.OutOfMemory;
    }

    const data_obj = try parseObjectField(att_obj, &.{"data"});
    const att_slot = try parseU64Field(data_obj, &.{"slot"});
    const head_obj = try parseObjectField(data_obj, &.{"head"});
    const target_obj = try parseObjectField(data_obj, &.{"target"});
    const source_obj = try parseObjectField(data_obj, &.{"source"});

    const att_data = types.AttestationData{
        .slot = att_slot,
        .head = .{
            .root = try parseRootField(head_obj, &.{"root"}),
            .slot = try parseU64Field(head_obj, &.{"slot"}),
        },
        .target = .{
            .root = try parseRootField(target_obj, &.{"root"}),
            .slot = try parseU64Field(target_obj, &.{"slot"}),
        },
        .source = .{
            .root = try parseRootField(source_obj, &.{"root"}),
            .slot = try parseU64Field(source_obj, &.{"slot"}),
        },
    };

    // For each validator in the aggregation bits, call onAttestation
    var indices = types.aggregationBitsToValidatorIndices(&aggregation_bits, driver.allocator) catch
        return error.InvalidField;
    defer indices.deinit(driver.allocator);

    for (indices.items) |vi| {
        const att = types.Attestation{
            .validator_id = @intCast(vi),
            .data = att_data,
        };
        driver.fork_choice.onAttestation(att, false) catch {};
    }
}

// ---------------------------------------------------------------------------
// Step dispatch & response building
// ---------------------------------------------------------------------------

/// Execute one fixture step against the driver and return an owned JSON response.
/// The caller must free the returned slice with `allocator`.
pub fn stepForkChoiceDriver(
    driver: *ForkChoiceDriverState,
    step_json: JsonValue,
    allocator: Allocator,
) ![]u8 {
    const step_obj = try requireObject(step_json);

    const step_type = try parseStringField(step_obj, &.{"stepType"});
    const valid = blk: {
        const v = step_obj.get("valid") orelse break :blk true;
        break :blk parseBoolValue(v) catch true;
    };

    const result = blk: {
        if (std.mem.eql(u8, step_type, "block")) {
            break :blk processBlockStep(driver, step_obj);
        } else if (std.mem.eql(u8, step_type, "tick")) {
            break :blk processTickStep(driver, step_obj);
        } else if (std.mem.eql(u8, step_type, "attestation")) {
            break :blk processAttestationStep(driver, step_obj);
        } else {
            break :blk error.UnknownStepType;
        }
    };

    const accepted: bool = if (result) |_| true else |_| false;
    const error_name: ?[]const u8 = if (result) |_| null else |err| @errorName(err);

    // The `accepted` field should match the `valid` flag when things are working correctly.
    // For the response: accepted = whether the step actually succeeded.
    _ = valid; // used only for local validation logic, not HTTP response

    return buildStepResponseJson(driver, accepted, error_name, allocator);
}

fn buildStepResponseJson(
    driver: *ForkChoiceDriverState,
    accepted: bool,
    error_msg: ?[]const u8,
    allocator: Allocator,
) ![]u8 {
    const head = driver.fork_choice.getHead();
    const justified = driver.fork_choice.getLatestJustified();
    const finalized = driver.fork_choice.getLatestFinalized();
    const safe_target = driver.fork_choice.getSafeTarget();
    const time = driver.fork_choice.fcStore.slot_clock.time.load(.monotonic);

    var writer_alloc: std.Io.Writer.Allocating = .init(allocator);
    defer writer_alloc.deinit();
    const w = &writer_alloc.writer;

    try w.print("{{\"accepted\":{s},", .{if (accepted) "true" else "false"});
    if (error_msg) |msg| {
        try w.print("\"error\":\"{s}\",", .{msg});
    } else {
        try w.writeAll("\"error\":null,");
    }
    try w.writeAll("\"snapshot\":{");
    try w.print("\"headSlot\":{d},", .{head.slot});
    try w.print("\"headRoot\":\"0x{x}\",", .{&head.blockRoot});
    try w.print("\"time\":{d},", .{time});
    try w.writeAll("\"justifiedCheckpoint\":{");
    try w.print("\"slot\":{d},\"root\":\"0x{x}\"", .{ justified.slot, &justified.root });
    try w.writeAll("},");
    try w.writeAll("\"finalizedCheckpoint\":{");
    try w.print("\"slot\":{d},\"root\":\"0x{x}\"", .{ finalized.slot, &finalized.root });
    try w.writeAll("},");
    try w.print("\"safeTarget\":\"0x{x}\"", .{&safe_target.blockRoot});
    try w.writeAll("}}");

    return allocator.dupe(u8, writer_alloc.writer.buffered());
}

/// Build a simple error JSON for init failure. Caller must free with allocator.
pub fn buildInitErrorJson(error_msg: []const u8, allocator: Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{{\"error\":\"{s}\"}}", .{error_msg});
}
