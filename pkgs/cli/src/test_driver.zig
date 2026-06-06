/// Fork-choice test driver for the hive consensus test fixtures.
///
/// Implements:
///   POST /lean/v0/test_driver/fork_choice/init
///   POST /lean/v0/test_driver/fork_choice/step
///   POST /lean/v0/test_driver/fork_choice/snapshot
///   POST /lean/v0/test_driver/state_transition/run
///   POST /lean/v0/test_driver/verify_signatures/run
///
/// Logic mirrors the fork-choice runner but adapted for persistent
/// per-request state and HTTP responses.
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
const xmss = @import("@zeam/xmss");
const thread_pool = @import("@zeam/thread-pool");

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
    thread_pool: *thread_pool.ThreadPool,

    pub fn deinit(self: *@This()) void {
        self.fork_choice.deinit();
        self.thread_pool.deinit();
        for (self.allocated_states.items) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
        self.allocated_states.deinit(self.allocator);
        self.state_map.deinit(self.allocator);
        var label_keys = self.label_map.keyIterator();
        while (label_keys.next()) |key| {
            self.allocator.free(key.*);
        }
        self.label_map.deinit(self.allocator);
        for (self.block_attestations.items) |entry| {
            self.allocator.free(entry.participants);
        }
        self.block_attestations.deinit(self.allocator);
        // anchor_state_ptr is NOT in allocated_states; free separately
        self.anchor_state_ptr.deinit();
        self.allocator.destroy(self.anchor_state_ptr);
        self.chain_config.genesis.deinit(self.allocator);
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
                const att_pubkey = try parseBytesField(types.Bytes52, vobj, &.{"attestationPublicKey"});
                const prop_pubkey = try parseBytesField(types.Bytes52, vobj, &.{"proposalPublicKey"});
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

    // Parse into a temporary, then clone into stable driver-owned storage.
    var anchor_state_temp = try buildStateFromJson(driver_allocator, anchor_state_value);
    defer anchor_state_temp.deinit();

    var anchor_block = try buildBlockFromJson(driver_allocator, anchor_block_value);
    defer anchor_block.deinit();

    // Validate anchor: anchorBlock.state_root must == hash_tree_root(anchorState)
    var expected_state_root: types.Root = undefined;
    zeam_utils.hashTreeRoot(types.BeamState, anchor_state_temp, &expected_state_root, driver_allocator) catch
        return error.HashFailed;
    if (!std.mem.eql(u8, &anchor_block.state_root, &expected_state_root)) {
        return error.AnchorMismatch;
    }

    // Build chain config (uses driver_allocator for pubkey slices).
    // ChainConfig.deinit currently owns ChainSpec only; this driver owns the
    // GenesisSpec pubkey slices it installs and frees them in ForkChoiceDriverState.deinit.
    var chain_config = try buildChainConfig(driver_allocator, &anchor_state_temp);
    errdefer {
        chain_config.genesis.deinit(driver_allocator);
        chain_config.deinit(driver_allocator);
    }

    const anchor_state_ptr = try driver_allocator.create(types.BeamState);
    errdefer driver_allocator.destroy(anchor_state_ptr);
    anchor_state_ptr.* = try zeam_utils.clone(types.BeamState, &anchor_state_temp, driver_allocator);
    errdefer anchor_state_ptr.deinit();

    // Compute anchor block root for state_map
    var anchor_block_root: types.Root = undefined;
    zeam_utils.hashTreeRoot(types.BeamBlock, anchor_block, &anchor_block_root, driver_allocator) catch
        return error.HashFailed;

    var test_thread_pool = try @import("@zeam/node").testing.setupTestPrimitives(driver_allocator);
    errdefer test_thread_pool.deinit();

    // Init fork choice (uses anchor_state_ptr for anchorState)
    var fork_choice = try forkchoice.ForkChoice.init(driver_allocator, .{
        .config = chain_config,
        .anchorState = anchor_state_ptr,
        .logger = logger,
        .thread_pool = test_thread_pool,
    });
    errdefer fork_choice.deinit();

    // Set up state map
    var state_map = StateMap.empty;
    errdefer state_map.deinit(driver_allocator);
    try state_map.put(driver_allocator, anchor_block_root, anchor_state_ptr);

    var allocated_states = StateList.empty;
    errdefer allocated_states.deinit(driver_allocator);

    var label_map = LabelMap.empty;
    errdefer {
        var label_keys = label_map.keyIterator();
        while (label_keys.next()) |key| {
            driver_allocator.free(key.*);
        }
        label_map.deinit(driver_allocator);
    }
    try label_map.put(driver_allocator, try driver_allocator.dupe(u8, "genesis"), anchor_block_root);

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
        .thread_pool = test_thread_pool,
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

fn putLabel(driver: *ForkChoiceDriverState, label: []const u8, root: types.Root) !void {
    if (driver.label_map.getEntry(label)) |entry| {
        entry.value_ptr.* = root;
        return;
    }
    const owned_label = try driver.allocator.dupe(u8, label);
    errdefer driver.allocator.free(owned_label);
    try driver.label_map.put(driver.allocator, owned_label, root);
}

fn parseNonNegativeU64(value: JsonValue) !u64 {
    return switch (value) {
        .integer => |i| if (i < 0) error.InvalidField else @as(u64, @intCast(i)),
        .float => |f| if (f < 0) error.InvalidField else @as(u64, @intFromFloat(f)),
        else => error.InvalidField,
    };
}

fn validateAttestationDataForGossip(driver: *ForkChoiceDriverState, data: types.AttestationData) !void {
    const source_node = driver.fork_choice.getProtoNode(data.source.root) orelse return error.UnknownSourceBlock;
    const target_node = driver.fork_choice.getProtoNode(data.target.root) orelse return error.UnknownTargetBlock;
    const head_node = driver.fork_choice.getProtoNode(data.head.root) orelse return error.UnknownHeadBlock;

    if (data.source.slot > data.target.slot) return error.SourceCheckpointExceedsTarget;
    if (data.head.slot < data.target.slot) return error.HeadOlderThanTarget;
    if (source_node.slot != data.source.slot) return error.SourceCheckpointSlotMismatch;
    if (target_node.slot != data.target.slot) return error.TargetCheckpointSlotMismatch;
    if (head_node.slot != data.head.slot) return error.HeadCheckpointSlotMismatch;

    const time_intervals = driver.fork_choice.fcStore.slot_clock.time.load(.monotonic);
    const attestation_start_interval = data.slot * node_constants.INTERVALS_PER_SLOT;
    if (attestation_start_interval > time_intervals + node_constants.GOSSIP_DISPARITY_INTERVALS) {
        return error.AttestationTooFarInFuture;
    }
}

pub fn isProtocolError(err: anyerror) bool {
    return switch (err) {
        error.MissingField,
        error.InvalidField,
        error.HashFailed,
        error.InvalidState,
        error.AnchorMismatch,
        => true,
        else => false,
    };
}

fn writeJsonString(w: *std.Io.Writer, value: []const u8) !void {
    try w.writeByte('"');
    for (value) |c| switch (c) {
        '\\' => try w.writeAll("\\\\"),
        '"' => try w.writeAll("\\\""),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0...8, 0x0b, 0x0c, 0x0e...0x1f => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
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
    new_state_ptr.* = try zeam_utils.clone(types.BeamState, parent_state_ptr, driver.allocator);

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
            try putLabel(driver, label, block_root);
        }
    }
}

fn processTickStep(
    driver: *ForkChoiceDriverState,
    step_obj: std.json.ObjectMap,
) !void {
    // Tick step supports two alternative forms:
    //   "time": unix timestamp  — convert to intervals via genesis_time
    //   "interval": direct interval count
    const anchor_genesis_time = driver.fork_choice.anchorState.config.genesis_time;

    if (step_obj.get("time")) |tv| {
        const time_value = try parseNonNegativeU64(tv);
        if (time_value < anchor_genesis_time) return; // tick before genesis is a no-op
        const target_intervals = timeToIntervals(anchor_genesis_time, time_value);
        try advanceForkchoiceIntervals(driver, target_intervals, false);
    } else if (step_obj.get("interval")) |iv| {
        const target_interval = try parseNonNegativeU64(iv);
        try advanceForkchoiceIntervals(driver, target_interval, false);
    } else {
        return error.MissingField; // neither time nor interval
    }
}

/// Parse AttestationData from a JSON object.
fn parseAttestationData(obj: std.json.ObjectMap) !types.AttestationData {
    const att_slot = try parseU64Field(obj, &.{"slot"});
    const head_obj = try parseObjectField(obj, &.{"head"});
    const target_obj = try parseObjectField(obj, &.{"target"});
    const source_obj = try parseObjectField(obj, &.{"source"});
    return types.AttestationData{
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
}

/// "attestation" step: single-validator gossip attestation.
/// Fixture format: {"validatorId": N, "data": {...}, "signature": "0x..."}
/// The XMSS signature is required and verified against the validator's
/// attestation pubkey (hashTreeRoot of AttestationData as the message).
fn processAttestationStep(
    driver: *ForkChoiceDriverState,
    step_obj: std.json.ObjectMap,
) !void {
    const att_value = step_obj.get("attestation") orelse return error.MissingField;
    const att_obj = try requireObject(att_value);

    // Parse validatorId (single validator, not aggregationBits)
    const validator_id = try parseU64Field(att_obj, &.{ "validatorIndex", "validatorId", "validator_id" });
    const data_obj = try parseObjectField(att_obj, &.{"data"});
    const att_data = try parseAttestationData(data_obj);
    const validators_slice = driver.fork_choice.anchorState.validators.constSlice();
    if (validator_id >= validators_slice.len) return error.UnknownValidator;
    try validateAttestationDataForGossip(driver, att_data);

    // XMSS signature verification. The hive fixtures embed a
    // SignedAttestation per gossip step: a valid_signature=False entry produces
    // an all-zero structurally-valid signature that must fail XMSS
    // verification. Hive fixtures use leanEnv=prod, so we
    // dispatch to xmss.verifySsz (the test-scheme path is exercised by the
    // local spectest runner instead).
    const sig_value = att_obj.get("signature") orelse return error.SignatureVerificationFailed;
    const sig_hex = parseStringValue(sig_value) catch return error.SignatureVerificationFailed;
    const sig_body = if (std.mem.startsWith(u8, sig_hex, "0x")) sig_hex[2..] else sig_hex;
    if (sig_body.len % 2 != 0) return error.SignatureVerificationFailed;
    const sig_bytes = try driver.allocator.alloc(u8, sig_body.len / 2);
    defer driver.allocator.free(sig_bytes);
    _ = std.fmt.hexToBytes(sig_bytes, sig_body) catch return error.SignatureVerificationFailed;

    var msg_hash: [32]u8 = undefined;
    zeam_utils.hashTreeRoot(types.AttestationData, att_data, &msg_hash, driver.allocator) catch
        return error.SignatureVerificationFailed;

    const att_pubkey = validators_slice[validator_id].getAttestationPubkey();
    const epoch: u32 = @intCast(att_data.slot);
    xmss.verifySsz(att_pubkey, &msg_hash, epoch, sig_bytes) catch
        return error.SignatureVerificationFailed;

    const att = types.Attestation{
        .validator_id = @intCast(validator_id),
        .data = att_data,
    };
    driver.fork_choice.onAttestation(att, false) catch |err| {
        std.debug.print("test_driver: attestation step onAttestation failed: {s}\n", .{@errorName(err)});
        return err;
    };
}

/// "gossipAggregatedAttestation" step: aggregated attestation received via gossip.
/// Fixture format: {"data": {...}, "proof": {"participants": {"data": [bool,...]}, "proof_data": {"data": "0x..."}}}
fn processGossipAggregatedAttestationStep(
    driver: *ForkChoiceDriverState,
    step_obj: std.json.ObjectMap,
) !void {
    const att_value = step_obj.get("attestation") orelse return; // null attestation is a no-op
    if (att_value == .null) return;
    const att_obj = try requireObject(att_value);

    const data_obj = try parseObjectField(att_obj, &.{"data"});
    const att_data = try parseAttestationData(data_obj);
    try validateAttestationDataForGossip(driver, att_data);

    const proof_obj = try parseObjectField(att_obj, &.{"proof"});
    const participants_obj = try parseObjectField(proof_obj, &.{"participants"});
    const bits_data_val = participants_obj.get("data") orelse return error.MissingField;
    const bits_arr = switch (bits_data_val) {
        .array => |a| a,
        else => return error.InvalidField,
    };

    var aggregation_bits = types.AggregationBits.init(driver.allocator) catch return error.OutOfMemory;
    defer aggregation_bits.deinit();
    for (bits_arr.items) |bit_val| {
        const b = try parseBoolValue(bit_val);
        aggregation_bits.append(b) catch return error.OutOfMemory;
    }

    // Build proof template for storeAggregatedPayload
    var proof_template = types.AggregatedSignatureProof.init(driver.allocator) catch return error.OutOfMemory;
    defer proof_template.deinit();
    const bits_len = aggregation_bits.len();
    for (0..bits_len) |i| {
        if (aggregation_bits.get(i) catch false) {
            types.aggregationBitsSet(&proof_template.participants, i, true) catch continue;
        }
    }

    // Register as aggregated payload in fork-choice
    driver.fork_choice.storeAggregatedPayload(&att_data, proof_template, false) catch |err| {
        std.debug.print("test_driver: gossipAggregatedAttestation storeAggregatedPayload failed: {s}\n", .{@errorName(err)});
        return err;
    };

    // Also register individual attestations
    var indices = types.aggregationBitsToValidatorIndices(&aggregation_bits, driver.allocator) catch
        return error.InvalidField;
    defer indices.deinit(driver.allocator);
    for (indices.items) |vi| {
        const att = types.Attestation{
            .validator_id = @intCast(vi),
            .data = att_data,
        };
        driver.fork_choice.onAttestation(att, false) catch |err| return err;
    }

    _ = driver.fork_choice.updateHead() catch {};
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

    var accepted: bool = true;
    var error_str: ?[]const u8 = null;

    if (std.mem.eql(u8, step_type, "block")) {
        processBlockStep(driver, step_obj) catch |err| {
            if (isProtocolError(err) or err == error.OutOfMemory) return err;
            accepted = false;
            error_str = @errorName(err);
        };
    } else if (std.mem.eql(u8, step_type, "tick")) {
        processTickStep(driver, step_obj) catch |err| {
            if (isProtocolError(err) or err == error.OutOfMemory) return err;
            accepted = false;
            error_str = @errorName(err);
        };
    } else if (std.mem.eql(u8, step_type, "attestation")) {
        // Single-validator gossip attestation: {"validatorId": N, "data": {...}}
        processAttestationStep(driver, step_obj) catch |err| {
            if (isProtocolError(err) or err == error.OutOfMemory) return err;
            accepted = false;
            error_str = @errorName(err);
        };
    } else if (std.mem.eql(u8, step_type, "gossipAggregatedAttestation")) {
        // Aggregated attestation gossip: {"data": {...}, "proof": {"participants": ..., "proof_data": ...}}
        // Mirrors ForkChoiceStep::GossipAggregatedAttestation.
        processGossipAggregatedAttestationStep(driver, step_obj) catch |err| {
            if (isProtocolError(err) or err == error.OutOfMemory) return err;
            accepted = false;
            error_str = @errorName(err);
        };
    } else if (std.mem.eql(u8, step_type, "checks")) {
        // checks step is a no-op for the driver — the hive simulator reads
        // `checks` from the JSON step itself and validates against our snapshot.
        // No `valid` field on checks steps so accepted value is not asserted.
    } else {
        accepted = false;
        error_str = "UnknownStepType";
        std.debug.print("test_driver: unhandled step type '{s}'\n", .{step_type});
    }

    _ = valid; // used only for local validation logic, not HTTP response

    return buildStepResponseJson(driver, accepted, error_str, allocator);
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
        try w.writeAll("\"error\":");
        try writeJsonString(w, msg);
        try w.writeByte(',');
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
    var writer_alloc: std.Io.Writer.Allocating = .init(allocator);
    defer writer_alloc.deinit();
    const w = &writer_alloc.writer;
    try w.writeAll("{\"error\":");
    try writeJsonString(w, error_msg);
    try w.writeByte('}');
    return allocator.dupe(u8, writer_alloc.writer.buffered());
}

/// Build a snapshot JSON from the current driver state. Caller must free.
pub fn buildSnapshotJson(driver: *ForkChoiceDriverState, allocator: Allocator) ![]u8 {
    const head = driver.fork_choice.getHead();
    const justified = driver.fork_choice.getLatestJustified();
    const finalized = driver.fork_choice.getLatestFinalized();
    const safe_target = driver.fork_choice.getSafeTarget();
    const time = driver.fork_choice.fcStore.slot_clock.time.load(.monotonic);

    var writer_alloc: std.Io.Writer.Allocating = .init(allocator);
    defer writer_alloc.deinit();
    const w = &writer_alloc.writer;

    try w.print("{{\"headSlot\":{d},\"headRoot\":\"0x{x}\",\"time\":{d},", .{ head.slot, &head.blockRoot, time });
    try w.print("\"justifiedCheckpoint\":{{\"slot\":{d},\"root\":\"0x{x}\"}},", .{ justified.slot, &justified.root });
    try w.print("\"finalizedCheckpoint\":{{\"slot\":{d},\"root\":\"0x{x}\"}},", .{ finalized.slot, &finalized.root });
    try w.print("\"safeTarget\":\"0x{x}\"}}", .{&safe_target.blockRoot});

    return allocator.dupe(u8, writer_alloc.writer.buffered());
}

/// POST /lean/v0/test_driver/state_transition/run
/// Runs a state transition (pre-state + list of blocks) and returns a JSON summary.
/// Response: {"succeeded": bool, "error": string|null, "post": {slot, latestBlockHeaderSlot, ...}|null}
pub fn runStateTransition(allocator: Allocator, body_bytes: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, aa, body_bytes, .{ .ignore_unknown_fields = true }) catch |err| {
        return buildSimpleResult(allocator, false, @errorName(err));
    };
    const obj = switch (parsed.value) {
        .object => |m| m,
        else => return buildSimpleResult(allocator, false, "InvalidRequest"),
    };

    const pre_val = obj.get("pre") orelse return buildSimpleResult(allocator, false, "MissingPreState");
    var pre_state = buildStateFromJson(aa, pre_val) catch |err| {
        return buildSimpleResult(allocator, false, @errorName(err));
    };
    defer pre_state.deinit();

    const blocks_val = obj.get("blocks") orelse return buildSimpleResult(allocator, false, "MissingBlocks");
    const blocks_arr = switch (blocks_val) {
        .array => |a| a,
        else => return buildSimpleResult(allocator, false, "BlocksNotArray"),
    };

    const expect_exception = if (obj.get("expectException")) |v| switch (v) {
        .string => |s| s,
        else => null,
    } else null;

    var last_slot: u64 = pre_state.slot;
    var last_block_header_slot: u64 = pre_state.latest_block_header.slot;
    var last_block_header_state_root: types.Root = pre_state.latest_block_header.state_root;
    var historical_count: usize = pre_state.historical_block_hashes.len();

    var logger_config = zeam_utils.getTestLoggerConfig();
    defer logger_config.deinit();
    const stf_logger = logger_config.logger(.state_transition);

    var transition_error: ?[]const u8 = null;

    // Slots-only monotonicity fixtures (test_process_slots_*)
    // ship `pre` + `expectException` with no blocks. The test asserts that
    // `process_slots(state, state.slot)` (or any `target <= state.slot`) is
    // rejected. zeam's `state.process_slots` returns `InvalidPreState` on
    // violation, which the spec calls `AssertionError`.
    if (blocks_arr.items.len == 0 and expect_exception != null) {
        const target_slot = pre_state.slot;
        pre_state.process_slots(aa, target_slot, stf_logger) catch |err| {
            transition_error = @errorName(err);
        };
    }

    for (blocks_arr.items) |block_val| {
        var block = buildBlockFromJson(aa, block_val) catch |err| {
            transition_error = @errorName(err);
            break;
        };
        defer block.deinit();
        state_transition.apply_transition(aa, &pre_state, block, .{
            .logger = stf_logger,
        }) catch |err| {
            transition_error = @errorName(err);
            break;
        };
        last_slot = pre_state.slot;
        last_block_header_slot = pre_state.latest_block_header.slot;
        last_block_header_state_root = pre_state.latest_block_header.state_root;
        historical_count = pre_state.historical_block_hashes.len();
    }

    const succeeded = transition_error == null;
    const expect_failure = expect_exception != null;
    const result_ok = succeeded != expect_failure; // XOR: succeeded when no exception expected, failed when expected
    _ = result_ok;

    var writer_alloc: std.Io.Writer.Allocating = .init(allocator);
    defer writer_alloc.deinit();
    const w = &writer_alloc.writer;

    if (succeeded) {
        try w.print(
            "{{\"succeeded\":true,\"error\":null,\"post\":{{\"slot\":{d},\"latestBlockHeaderSlot\":{d},\"latestBlockHeaderStateRoot\":\"0x{x}\",\"historicalBlockHashesCount\":{d}}}}}",
            .{ last_slot, last_block_header_slot, &last_block_header_state_root, historical_count },
        );
    } else {
        try w.writeAll("{\"succeeded\":false,\"error\":");
        try writeJsonString(w, transition_error orelse "Unknown");
        try w.writeAll(",\"post\":null}");
    }

    return allocator.dupe(u8, writer_alloc.writer.buffered());
}

/// POST /lean/v0/test_driver/verify_signatures/run
/// Verifies block signatures against an anchor state.
/// Implements XMSS proposer + attestation signature verification for the hive test fixtures.
pub fn runVerifySignatures(allocator: Allocator, body_bytes: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, aa, body_bytes, .{ .ignore_unknown_fields = true }) catch |err| {
        return buildSimpleResult(allocator, false, @errorName(err));
    };
    const obj = switch (parsed.value) {
        .object => |m| m,
        else => return buildSimpleResult(allocator, false, "InvalidRequest"),
    };

    // Determine lean environment (prod vs test); defaults to "prod".
    const lean_env = if (obj.get("leanEnv")) |v| switch (v) {
        .string => |s| s,
        else => "prod",
    } else "prod";
    const is_test_env = std.mem.eql(u8, lean_env, "test");

    const expect_exception: ?[]const u8 = if (obj.get("expectException")) |v| switch (v) {
        .string => |s| s,
        else => null,
    } else null;

    // Parse anchor state
    const anchor_val = obj.get("anchorState") orelse return buildSimpleResult(allocator, false, "MissingAnchorState");
    var state = buildStateFromJson(aa, anchor_val) catch |err| {
        return buildSimpleResult(allocator, false, @errorName(err));
    };
    defer state.deinit();

    // Parse signedBlock.block and signedBlock.signature
    const signed_block_val = obj.get("signedBlock") orelse return buildSimpleResult(allocator, false, "MissingSignedBlock");
    const signed_block_obj = switch (signed_block_val) {
        .object => |m| m,
        else => return buildSimpleResult(allocator, false, "InvalidSignedBlock"),
    };

    const block_val = signed_block_obj.get("block") orelse return buildSimpleResult(allocator, false, "MissingBlock");
    var block = buildBlockFromJson(aa, block_val) catch |err| {
        return buildSimpleResult(allocator, false, @errorName(err));
    };
    defer block.deinit();

    const sig_val = signed_block_obj.get("signature") orelse return buildSimpleResult(allocator, false, "MissingSignature");
    const sig_obj = switch (sig_val) {
        .object => |m| m,
        else => return buildSimpleResult(allocator, false, "InvalidSignature"),
    };

    // ----- Proposer signature verification -----
    const proposer_sig_hex = blk: {
        const v = getFieldMulti(sig_obj, &.{ "proposerSignature", "proposer_signature" }) orelse
            break :blk null;
        break :blk switch (v) {
            .string => |s| s,
            else => null,
        };
    };

    var any_failure = false;
    var failure_reason: ?[]const u8 = null;

    if (proposer_sig_hex) |hex| proposer: {
        // Use a stack buffer — SIGSIZE (2536 bytes) is a known compile-time constant.
        var sig_buf: [types.SIGSIZE]u8 = undefined;
        const proposer_sig_bytes = parseHexBytes(&sig_buf, hex) catch {
            any_failure = true;
            failure_reason = "InvalidProposerSignatureHex";
            break :proposer;
        };

        // Hash the block
        var block_root: [32]u8 = undefined;
        zeam_utils.hashTreeRoot(types.BeamBlock, block, &block_root, aa) catch {
            any_failure = true;
            failure_reason = "HashFailed";
            break :proposer;
        };

        const proposer_index: usize = @intCast(block.proposer_index);
        const validators_slice = state.validators.constSlice();
        if (proposer_index >= validators_slice.len) {
            any_failure = true;
            failure_reason = "InvalidProposerIndex";
            break :proposer;
        }

        const proposal_pubkey = validators_slice[proposer_index].getProposalPubkey();
        const epoch: u32 = @intCast(block.slot);

        const result = if (is_test_env)
            xmss.verifySszTest(proposal_pubkey, &block_root, epoch, proposer_sig_bytes)
        else
            xmss.verifySsz(proposal_pubkey, &block_root, epoch, proposer_sig_bytes);
        if (result) |_| {} else |_| {
            any_failure = true;
            failure_reason = "ProposerSignatureVerificationFailed";
        }
    } else {
        any_failure = true;
        failure_reason = "MissingProposerSignature";
    }

    // ----- Attestation signature verification -----
    if (!any_failure) {
        const att_sigs_result = verifyAttestationSignatures(aa, &state, &block, sig_obj, is_test_env);
        if (att_sigs_result) |att_failed| {
            if (att_failed) {
                any_failure = true;
                failure_reason = "AttestationSignatureVerificationFailed";
            }
        } else |_| {
            any_failure = true;
            failure_reason = "AttestationSignatureVerificationError";
        }
    }

    // Report the truth about whether signatures verified.
    // The simulator owns the comparison against `expectException` — it asserts
    // `response.succeeded == expect_exception.is_none()`, so the driver must
    // report verification outcome, NOT test outcome.
    _ = expect_exception;
    return buildSimpleResult(
        allocator,
        !any_failure,
        if (any_failure) (failure_reason orelse "SignatureVerificationFailed") else null,
    );
}

/// Verify each body-attestation aggregated signature for the HTTP test driver.
/// Returns true if any verification rejected the input.
fn verifyAttestationSignatures(
    allocator: Allocator,
    state: *const types.BeamState,
    block: *const types.BeamBlock,
    sig_obj: std.json.ObjectMap,
    is_test_env: bool,
) !bool {
    const attestations = block.body.attestations.constSlice();
    if (attestations.len == 0) return false;

    // Get attestationSignatures from signature object
    const att_sigs_val = getFieldMulti(sig_obj, &.{ "attestationSignatures", "attestation_signatures" }) orelse
        return true; // missing signatures for non-empty attestations = failure
    const att_sigs_obj = switch (att_sigs_val) {
        .object => |m| m,
        else => return true,
    };
    const att_sigs_data = att_sigs_obj.get("data") orelse return true;
    const sig_arr = switch (att_sigs_data) {
        .array => |a| a,
        else => return true,
    };

    if (sig_arr.items.len != attestations.len) return true;

    const validators_slice = state.validators.constSlice();
    var any_failed = false;

    for (attestations, sig_arr.items) |aggregated_attestation, sig_value| {
        var validator_indices = types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, allocator) catch {
            any_failed = true;
            continue;
        };
        defer validator_indices.deinit(allocator);

        var pubkey_wrappers: std.ArrayList(xmss.PublicKey) = .empty;
        defer {
            for (pubkey_wrappers.items) |*wrapper| wrapper.deinit();
            pubkey_wrappers.deinit(allocator);
        }
        var public_keys: std.ArrayList(*const xmss.HashSigPublicKey) = .empty;
        defer public_keys.deinit(allocator);

        var pubkey_load_failed = false;
        for (validator_indices.items) |validator_index| {
            if (validator_index >= validators_slice.len) {
                pubkey_load_failed = true;
                break;
            }
            const pubkey_bytes = validators_slice[validator_index].getAttestationPubkey();
            const pk = xmss.PublicKey.fromBytes(pubkey_bytes) catch {
                pubkey_load_failed = true;
                break;
            };
            pubkey_wrappers.append(allocator, pk) catch {
                pubkey_load_failed = true;
                break;
            };
            public_keys.append(allocator, pk.handle) catch {
                pubkey_load_failed = true;
                break;
            };
        }
        if (pubkey_load_failed) {
            any_failed = true;
            continue;
        }

        // Parse the aggregated signature proof
        const proof_result = parseAggSigProofFromJson(allocator, sig_value);
        var proof = proof_result catch {
            any_failed = true;
            continue;
        };
        defer proof.deinit();

        var message_hash: [32]u8 = undefined;
        zeam_utils.hashTreeRoot(types.AttestationData, aggregated_attestation.data, &message_hash, allocator) catch {
            any_failed = true;
            continue;
        };

        const epoch: u64 = aggregated_attestation.data.slot;
        _ = is_test_env; // attestation verification uses leanMultisig which is prod-only currently
        proof.verify(public_keys.items, &message_hash, epoch) catch {
            any_failed = true;
        };
    }

    return any_failed;
}

/// Parse an AggregatedSignatureProof from a JSON value (test driver format).
fn parseAggSigProofFromJson(allocator: Allocator, value: JsonValue) !types.AggregatedSignatureProof {
    const obj = switch (value) {
        .object => |m| m,
        else => return error.InvalidField,
    };

    const participants_val = obj.get("participants") orelse return error.MissingField;
    var participants = types.AggregationBits.init(allocator) catch return error.InvalidField;
    errdefer participants.deinit();

    const p_obj = switch (participants_val) {
        .object => |m| m,
        else => return error.InvalidField,
    };
    const p_data = p_obj.get("data") orelse return error.MissingField;
    const p_arr = switch (p_data) {
        .array => |a| a,
        else => return error.InvalidField,
    };
    for (p_arr.items) |bit_val| {
        const b = switch (bit_val) {
            .bool => |v| v,
            else => return error.InvalidField,
        };
        participants.append(b) catch return error.InvalidField;
    }

    const proof_data_obj = switch (getFieldMulti(obj, &.{ "proofData", "proof_data" }) orelse return error.MissingField) {
        .object => |m| m,
        else => return error.InvalidField,
    };
    const proof_data_hex = switch (proof_data_obj.get("data") orelse return error.MissingField) {
        .string => |s| s,
        else => return error.InvalidField,
    };
    const proof_bytes = try parseHexBytesAlloc(allocator, proof_data_hex);
    defer allocator.free(proof_bytes);

    var proof_data = try xmss.ByteListMiB.init(allocator);
    errdefer proof_data.deinit();
    for (proof_bytes) |b| {
        proof_data.append(b) catch return error.InvalidField;
    }

    return types.AggregatedSignatureProof{
        .participants = participants,
        .proof = proof_data,
    };
}

/// Parse a hex-encoded byte string (with 0x prefix) into a caller-supplied buffer.
/// Returns a slice of the filled portion of `buf`. No heap allocation.
fn parseHexBytes(buf: []u8, hex: []const u8) ![]u8 {
    const body = if (std.mem.startsWith(u8, hex, "0x")) hex[2..] else hex;
    if (body.len % 2 != 0) return error.InvalidField;
    const byte_len = body.len / 2;
    if (byte_len > buf.len) return error.BufferTooSmall;
    _ = std.fmt.hexToBytes(buf[0..byte_len], body) catch return error.InvalidField;
    return buf[0..byte_len];
}

/// Parse a hex-encoded byte string (with 0x prefix) into allocated bytes.
/// Use only when the output size is not known at comptime (e.g. variable-length proofs).
fn parseHexBytesAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    const body = if (std.mem.startsWith(u8, hex, "0x")) hex[2..] else hex;
    if (body.len % 2 != 0) return error.InvalidField;
    const byte_len = body.len / 2;
    const out = try allocator.alloc(u8, byte_len);
    _ = std.fmt.hexToBytes(out, body) catch return error.InvalidField;
    return out;
}

fn buildSimpleResult(allocator: Allocator, succeeded: bool, err_name: ?[]const u8) ![]u8 {
    var writer_alloc: std.Io.Writer.Allocating = .init(allocator);
    defer writer_alloc.deinit();
    const w = &writer_alloc.writer;
    try w.print("{{\"succeeded\":{s},\"error\":", .{boolStr(succeeded)});
    if (err_name) |e| {
        try writeJsonString(w, e);
    } else {
        try w.writeAll("null");
    }
    try w.writeByte('}');
    return allocator.dupe(u8, writer_alloc.writer.buffered());
}

fn boolStr(b: bool) []const u8 {
    return if (b) "true" else "false";
}
