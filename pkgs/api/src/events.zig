const std = @import("std");
const json = std.json;
const types = @import("@zeam/types");

/// SSE Event types for chain state changes
pub const ChainEventType = enum {
    new_head,
    new_justification,
    new_finalization,
};

/// New head event data
pub const NewHeadEvent = struct {
    slot: u64,
    block_root: []const u8,
    parent_root: []const u8,
    state_root: []const u8,
    timely: bool,

    pub fn fromProtoBlock(allocator: std.mem.Allocator, proto_block: types.ProtoBlock) !NewHeadEvent {
        const block_root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&proto_block.blockRoot)});
        const parent_root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&proto_block.parentRoot)});
        const state_root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&proto_block.stateRoot)});

        return NewHeadEvent{
            .slot = proto_block.slot,
            .block_root = block_root_hex,
            .parent_root = parent_root_hex,
            .state_root = state_root_hex,
            .timely = proto_block.timeliness,
        };
    }

    pub fn deinit(self: *NewHeadEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.block_root);
        allocator.free(self.parent_root);
        allocator.free(self.state_root);
    }
};

/// New justification event data
pub const NewJustificationEvent = struct {
    slot: u64,
    root: []const u8,
    justified_slot: u64,

    pub fn fromCheckpoint(allocator: std.mem.Allocator, checkpoint: types.Mini3SFCheckpoint, current_slot: u64) !NewJustificationEvent {
        const root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&checkpoint.root)});

        return NewJustificationEvent{
            .slot = current_slot,
            .root = root_hex,
            .justified_slot = checkpoint.slot,
        };
    }

    pub fn deinit(self: *NewJustificationEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.root);
    }
};

/// New finalization event data
pub const NewFinalizationEvent = struct {
    slot: u64,
    root: []const u8,
    finalized_slot: u64,

    pub fn fromCheckpoint(allocator: std.mem.Allocator, checkpoint: types.Mini3SFCheckpoint, current_slot: u64) !NewFinalizationEvent {
        const root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&checkpoint.root)});

        return NewFinalizationEvent{
            .slot = current_slot,
            .root = root_hex,
            .finalized_slot = checkpoint.slot,
        };
    }

    pub fn deinit(self: *NewFinalizationEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.root);
    }
};

/// Union type for all chain events
pub const ChainEvent = union(ChainEventType) {
    new_head: NewHeadEvent,
    new_justification: NewJustificationEvent,
    new_finalization: NewFinalizationEvent,

    pub fn deinit(self: *ChainEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .new_head => |*event| event.deinit(allocator),
            .new_justification => |*event| event.deinit(allocator),
            .new_finalization => |*event| event.deinit(allocator),
        }
    }
};

/// Serialize a chain event to JSON for SSE
pub fn serializeEventToJson(allocator: std.mem.Allocator, event: ChainEvent) ![]u8 {
    const event_name = switch (event) {
        .new_head => "new_head",
        .new_justification => "new_justification",
        .new_finalization => "new_finalization",
    };

    var json_str = std.ArrayList(u8).init(allocator);
    defer json_str.deinit();

    // Format as SSE event
    try json_str.appendSlice("event: ");
    try json_str.appendSlice(event_name);
    try json_str.appendSlice("\ndata: ");

    // Serialize the data based on event type
    switch (event) {
        .new_head => |head_event| {
            var data_obj = json.ObjectMap.init(allocator);
            try data_obj.put("slot", json.Value{ .integer = @as(i64, @intCast(head_event.slot)) });
            try data_obj.put("block_root", json.Value{ .string = head_event.block_root });
            try data_obj.put("parent_root", json.Value{ .string = head_event.parent_root });
            try data_obj.put("state_root", json.Value{ .string = head_event.state_root });
            try data_obj.put("timely", json.Value{ .bool = head_event.timely });

            const data_value = json.Value{ .object = data_obj };
            try json.stringify(data_value, .{}, json_str.writer());
        },
        .new_justification => |just_event| {
            var data_obj = json.ObjectMap.init(allocator);
            try data_obj.put("slot", json.Value{ .integer = @as(i64, @intCast(just_event.slot)) });
            try data_obj.put("root", json.Value{ .string = just_event.root });
            try data_obj.put("justified_slot", json.Value{ .integer = @as(i64, @intCast(just_event.justified_slot)) });

            const data_value = json.Value{ .object = data_obj };
            try json.stringify(data_value, .{}, json_str.writer());
        },
        .new_finalization => |final_event| {
            var data_obj = json.ObjectMap.init(allocator);
            try data_obj.put("slot", json.Value{ .integer = @as(i64, @intCast(final_event.slot)) });
            try data_obj.put("root", json.Value{ .string = final_event.root });
            try data_obj.put("finalized_slot", json.Value{ .integer = @as(i64, @intCast(final_event.finalized_slot)) });

            const data_value = json.Value{ .object = data_obj };
            try json.stringify(data_value, .{}, json_str.writer());
        },
    }

    try json_str.appendSlice("\n\n");

    return json_str.toOwnedSlice();
}

test "serialize new head event" {
    const allocator = std.testing.allocator;

    const proto_block = types.ProtoBlock{
        .slot = 123,
        .blockRoot = [_]u8{1} ** 32,
        .parentRoot = [_]u8{2} ** 32,
        .stateRoot = [_]u8{3} ** 32,
        .timeliness = true,
    };

    const head_event = try NewHeadEvent.fromProtoBlock(allocator, proto_block);
    defer head_event.deinit(allocator);

    const chain_event = ChainEvent{ .new_head = head_event };
    const json_str = try serializeEventToJson(allocator, chain_event);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "event: new_head") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"slot\":123") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"timely\":true") != null);
}

test "serialize new justification event" {
    const allocator = std.testing.allocator;

    const checkpoint = types.Mini3SFCheckpoint{
        .slot = 120,
        .root = [_]u8{5} ** 32,
    };

    const just_event = try NewJustificationEvent.fromCheckpoint(allocator, checkpoint, 123);
    defer just_event.deinit(allocator);

    const chain_event = ChainEvent{ .new_justification = just_event };
    const json_str = try serializeEventToJson(allocator, chain_event);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "event: new_justification") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"slot\":123") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"justified_slot\":120") != null);
}

test "serialize new finalization event" {
    const allocator = std.testing.allocator;

    const checkpoint = types.Mini3SFCheckpoint{
        .slot = 100,
        .root = [_]u8{4} ** 32,
    };

    const final_event = try NewFinalizationEvent.fromCheckpoint(allocator, checkpoint, 123);
    defer final_event.deinit(allocator);

    const chain_event = ChainEvent{ .new_finalization = final_event };
    const json_str = try serializeEventToJson(allocator, chain_event);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "event: new_finalization") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"slot\":123") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"finalized_slot\":100") != null);
}
