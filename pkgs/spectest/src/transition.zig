const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;
const types = @import("@zeam/types");
const state_transition = @import("@zeam/state-transition");
const zeam_utils = @import("@zeam/utils");
const ssz = @import("ssz");

const TransitionError = error{
    InvalidArgs,
    FileNotFound,
    JsonParseError,
    TransitionFailed,
    OutputWriteFailed,
};

fn printUsage() void {
    std.debug.print("Usage: spectest-transition <input_state> <block> <output_state>\n", .{});
    std.debug.print("  <input_state>:  Input BeamState JSON file path or '-' for stdin\n", .{});
    std.debug.print("  <block>:        Block JSON file path or '-' for stdin (sequential)\n", .{});
    std.debug.print("  <output_state>: Output BeamState JSON file path or '-' for stdout\n", .{});
}

fn readJsonFromFile(allocator: Allocator, path: []const u8) !json.Parsed(json.Value) {
    if (std.mem.eql(u8, path, "-")) {
        const stdin = std.io.getStdIn();
        const content = try stdin.reader().readAllAlloc(allocator, 1024 * 1024 * 100); // 100MB max
        defer allocator.free(content);
        return json.parseFromSlice(json.Value, allocator, content, .{});
    }

    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        std.debug.print("Error opening file '{s}': {}\n", .{ path, err });
        return TransitionError.FileNotFound;
    };
    defer file.close();

    const file_size = try file.getEndPos();
    const content = try allocator.alloc(u8, file_size);
    defer allocator.free(content);
    _ = try file.read(content);

    return json.parseFromSlice(json.Value, allocator, content, .{});
}

fn writeJsonToFile(allocator: Allocator, path: []const u8, value: json.Value) !void {
    const json_string = try zeam_utils.jsonToString(allocator, value);
    defer allocator.free(json_string);

    if (std.mem.eql(u8, path, "-")) {
        const stdout = std.io.getStdOut();
        try stdout.writer().writeAll(json_string);
        try stdout.writer().writeByte('\n');
    } else {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        try file.writeAll(json_string);
        try file.writer().writeByte('\n');
    }
}

fn parseBeamState(allocator: Allocator, json_value: json.Value) !types.BeamState {
    const obj = json_value.object;

    // Parse config
    const config_obj = obj.get("config").?.object;
    const config = types.BeamStateConfig{
        .num_validators = @intCast(config_obj.get("num_validators").?.integer),
        .genesis_time = @intCast(config_obj.get("genesis_time").?.integer),
    };

    // Parse slot
    const slot: u64 = @intCast(obj.get("slot").?.integer);

    // Parse latest_block_header
    const header_obj = obj.get("latest_block_header").?.object;
    var latest_block_header = types.BeamBlockHeader{
        .slot = @intCast(header_obj.get("slot").?.integer),
        .proposer_index = @intCast(header_obj.get("proposer_index").?.integer),
        .parent_root = undefined,
        .state_root = undefined,
        .body_root = undefined,
    };
    _ = try std.fmt.hexToBytes(&latest_block_header.parent_root, header_obj.get("parent_root").?.string[2..]);
    _ = try std.fmt.hexToBytes(&latest_block_header.state_root, header_obj.get("state_root").?.string[2..]);
    _ = try std.fmt.hexToBytes(&latest_block_header.body_root, header_obj.get("body_root").?.string[2..]);

    // Parse checkpoints
    const latest_justified_obj = obj.get("latest_justified").?.object;
    var latest_justified = types.Mini3SFCheckpoint{
        .root = undefined,
        .slot = @intCast(latest_justified_obj.get("slot").?.integer),
    };
    _ = try std.fmt.hexToBytes(&latest_justified.root, latest_justified_obj.get("root").?.string[2..]);

    const latest_finalized_obj = obj.get("latest_finalized").?.object;
    var latest_finalized = types.Mini3SFCheckpoint{
        .root = undefined,
        .slot = @intCast(latest_finalized_obj.get("slot").?.integer),
    };
    _ = try std.fmt.hexToBytes(&latest_finalized.root, latest_finalized_obj.get("root").?.string[2..]);

    // Initialize lists
    var historical_block_hashes = try types.HistoricalBlockHashes.init(allocator);
    errdefer historical_block_hashes.deinit();
    
    if (obj.get("historical_block_hashes")) |hashes| {
        for (hashes.array.items) |hash_str| {
            var hash: types.Root = undefined;
            _ = try std.fmt.hexToBytes(&hash, hash_str.string[2..]);
            try historical_block_hashes.append(hash);
        }
    }

    var justified_slots = try types.JustifiedSlots.init(allocator);
    errdefer justified_slots.deinit();
    
    if (obj.get("justified_slots")) |slots| {
        for (slots.array.items) |slot_val| {
            const slot_idx: usize = @intCast(slot_val.integer);
            try justified_slots.set(slot_idx, true);
        }
    }

    var justifications_roots = try types.JustificationsRoots.init(allocator);
    errdefer justifications_roots.deinit();
    
    if (obj.get("justifications_roots")) |roots| {
        for (roots.array.items) |root_str| {
            var root: types.Root = undefined;
            _ = try std.fmt.hexToBytes(&root, root_str.string[2..]);
            try justifications_roots.append(root);
        }
    }

    var justifications_validators = try types.JustificationsValidators.init(allocator);
    errdefer justifications_validators.deinit();
    
    if (obj.get("justifications_validators")) |validators| {
        for (validators.array.items) |val| {
            try justifications_validators.append(val.bool);
        }
    }

    return types.BeamState{
        .config = config,
        .slot = slot,
        .latest_block_header = latest_block_header,
        .latest_justified = latest_justified,
        .latest_finalized = latest_finalized,
        .historical_block_hashes = historical_block_hashes,
        .justified_slots = justified_slots,
        .justifications_roots = justifications_roots,
        .justifications_validators = justifications_validators,
    };
}

fn parseSignedBeamBlock(allocator: Allocator, json_value: json.Value) !types.SignedBeamBlock {
    const obj = json_value.object;
    const message_obj = obj.get("message").?.object;

    // Parse the block header fields
    const slot: u64 = @intCast(message_obj.get("slot").?.integer);
    const proposer_index: u64 = @intCast(message_obj.get("proposer_index").?.integer);
    
    var parent_root: types.Root = undefined;
    var state_root: types.Root = undefined;
    
    _ = try std.fmt.hexToBytes(&parent_root, message_obj.get("parent_root").?.string[2..]);
    _ = try std.fmt.hexToBytes(&state_root, message_obj.get("state_root").?.string[2..]);

    // Parse the body
    const body_obj = message_obj.get("body").?.object;
    var attestations = try types.SignedVotes.init(allocator);
    errdefer attestations.deinit();

    if (body_obj.get("attestations")) |attestations_array| {
        for (attestations_array.array.items) |att_obj| {
            const validator_id: u64 = @intCast(att_obj.object.get("validator_id").?.integer);
            const message_obj_vote = att_obj.object.get("message").?.object;
            
            // Parse Mini3SFVote message
            const vote_slot: u64 = @intCast(message_obj_vote.get("slot").?.integer);
            
            // Parse head checkpoint
            const head_obj = message_obj_vote.get("head").?.object;
            var head_root: types.Root = undefined;
            _ = try std.fmt.hexToBytes(&head_root, head_obj.get("root").?.string[2..]);
            const head = types.Mini3SFCheckpoint{
                .root = head_root,
                .slot = @intCast(head_obj.get("slot").?.integer),
            };
            
            // Parse target checkpoint  
            const target_obj = message_obj_vote.get("target").?.object;
            var target_root: types.Root = undefined;
            _ = try std.fmt.hexToBytes(&target_root, target_obj.get("root").?.string[2..]);
            const target = types.Mini3SFCheckpoint{
                .root = target_root,
                .slot = @intCast(target_obj.get("slot").?.integer),
            };
            
            // Parse source checkpoint
            const source_obj = message_obj_vote.get("source").?.object;
            var source_root: types.Root = undefined;
            _ = try std.fmt.hexToBytes(&source_root, source_obj.get("root").?.string[2..]);
            const source = types.Mini3SFCheckpoint{
                .root = source_root,
                .slot = @intCast(source_obj.get("slot").?.integer),
            };
            
            const message = types.Mini3SFVote{
                .slot = vote_slot,
                .head = head,
                .target = target,
                .source = source,
            };

            var signature: types.Bytes4000 = undefined;
            const sig_str = att_obj.object.get("signature").?.string[2..];
            const sig_bytes = try allocator.alloc(u8, sig_str.len / 2);
            defer allocator.free(sig_bytes);
            _ = try std.fmt.hexToBytes(sig_bytes, sig_str);
            @memcpy(signature[0..sig_bytes.len], sig_bytes);

            const attestation = types.SignedVote{
                .validator_id = validator_id,
                .message = message,
                .signature = signature,
            };
            try attestations.append(attestation);
        }
    }

    const body = types.BeamBlockBody{
        .attestations = attestations,
    };

    const message = types.BeamBlock{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = parent_root,
        .state_root = state_root,
        .body = body,
    };

    // Parse signature
    var signature: types.Bytes4000 = undefined;
    const sig_str = obj.get("signature").?.string[2..];
    const sig_bytes = try allocator.alloc(u8, sig_str.len / 2);
    defer allocator.free(sig_bytes);
    _ = try std.fmt.hexToBytes(sig_bytes, sig_str);
    @memcpy(signature[0..sig_bytes.len], sig_bytes);

    return types.SignedBeamBlock{
        .message = message,
        .signature = signature,
    };
}

fn stateToJson(allocator: Allocator, state: *const types.BeamState) !json.Value {
    var obj = json.ObjectMap.init(allocator);

    // Add config
    try obj.put("config", try state.config.toJson(allocator));

    // Add slot
    try obj.put("slot", json.Value{ .integer = @intCast(state.slot) });

    // Add latest_block_header
    var header_obj = json.ObjectMap.init(allocator);
    try header_obj.put("slot", json.Value{ .integer = @intCast(state.latest_block_header.slot) });
    try header_obj.put("proposer_index", json.Value{ .integer = @intCast(state.latest_block_header.proposer_index) });
    
    const parent_root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&state.latest_block_header.parent_root)});
    const state_root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&state.latest_block_header.state_root)});
    const body_root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&state.latest_block_header.body_root)});
    
    try header_obj.put("parent_root", json.Value{ .string = parent_root_hex });
    try header_obj.put("state_root", json.Value{ .string = state_root_hex });
    try header_obj.put("body_root", json.Value{ .string = body_root_hex });
    try obj.put("latest_block_header", json.Value{ .object = header_obj });

    // Add checkpoints
    var justified_obj = json.ObjectMap.init(allocator);
    const justified_root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&state.latest_justified.root)});
    try justified_obj.put("root", json.Value{ .string = justified_root_hex });
    try justified_obj.put("slot", json.Value{ .integer = @intCast(state.latest_justified.slot) });
    try obj.put("latest_justified", json.Value{ .object = justified_obj });

    var finalized_obj = json.ObjectMap.init(allocator);
    const finalized_root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&state.latest_finalized.root)});
    try finalized_obj.put("root", json.Value{ .string = finalized_root_hex });
    try finalized_obj.put("slot", json.Value{ .integer = @intCast(state.latest_finalized.slot) });
    try obj.put("latest_finalized", json.Value{ .object = finalized_obj });

    // Add historical_block_hashes
    var hashes_array = std.ArrayList(json.Value).init(allocator);
    for (state.historical_block_hashes.constSlice()) |hash| {
        const hash_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&hash)});
        try hashes_array.append(json.Value{ .string = hash_hex });
    }
    try obj.put("historical_block_hashes", json.Value{ .array = hashes_array });

    // Add justified_slots (as array of slot indices that are set)
    var slots_array = std.ArrayList(json.Value).init(allocator);
    var i: usize = 0;
    while (i < state.justified_slots.len()) : (i += 1) {
        if (try state.justified_slots.get(i)) {
            try slots_array.append(json.Value{ .integer = @intCast(i) });
        }
    }
    try obj.put("justified_slots", json.Value{ .array = slots_array });

    // Add justifications_roots
    var roots_array = std.ArrayList(json.Value).init(allocator);
    for (state.justifications_roots.constSlice()) |root| {
        const root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&root)});
        try roots_array.append(json.Value{ .string = root_hex });
    }
    try obj.put("justifications_roots", json.Value{ .array = roots_array });

    // Add justifications_validators
    var validators_array = std.ArrayList(json.Value).init(allocator);
    i = 0;
    while (i < state.justifications_validators.len()) : (i += 1) {
        const val = try state.justifications_validators.get(i);
        try validators_array.append(json.Value{ .bool = val });
    }
    try obj.put("justifications_validators", json.Value{ .array = validators_array });

    return json.Value{ .object = obj };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 4) {
        printUsage();
        return TransitionError.InvalidArgs;
    }

    const input_state_path = args[1];
    const block_path = args[2];
    const output_state_path = args[3];

    // Read input state
    const state_json = try readJsonFromFile(allocator, input_state_path);
    defer state_json.deinit();
    
    var state = try parseBeamState(allocator, state_json.value);
    defer state.deinit();

    // Read block
    const block_json = try readJsonFromFile(allocator, block_path);
    defer block_json.deinit();
    
    var signed_block = try parseSignedBeamBlock(allocator, block_json.value);
    defer signed_block.deinit();

    // Create logger for state transition
    var zeam_logger_config = zeam_utils.getLoggerConfig(.err, null);
    const logger = zeam_logger_config.logger(.state_transition);

    // Apply transition
    const opts = state_transition.StateTransitionOpts{
        .validSignatures = true,
        .validateResult = true,
        .logger = logger,
    };
    
    try state_transition.apply_transition(allocator, &state, signed_block, opts);

    // Write output state
    const output_json = try stateToJson(allocator, &state);
    try writeJsonToFile(allocator, output_state_path, output_json);
}