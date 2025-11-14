const std = @import("std");
const types = @import("@zeam/types");
const utils = @import("@zeam/utils");

const Allocator = std.mem.Allocator;
const Checkpoint = types.Checkpoint;

const json = std.json;
const jsonToString = utils.jsonToString;

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

    pub fn fromProtoBlock(allocator: Allocator, proto_block: types.ProtoBlock) !NewHeadEvent {
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

    pub fn toJson(self: *const NewHeadEvent, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("block_root", json.Value{ .string = self.block_root });
        try obj.put("parent_root", json.Value{ .string = self.parent_root });
        try obj.put("state_root", json.Value{ .string = self.state_root });
        try obj.put("timely", json.Value{ .bool = self.timely });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const NewHeadEvent, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer json_value.object.deinit();
        return jsonToString(allocator, json_value);
    }

    pub fn deinit(self: *NewHeadEvent, allocator: Allocator) void {
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

    pub fn fromCheckpoint(allocator: Allocator, checkpoint: Checkpoint, current_slot: u64) !NewJustificationEvent {
        const root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&checkpoint.root)});

        return NewJustificationEvent{
            .slot = current_slot,
            .root = root_hex,
            .justified_slot = checkpoint.slot,
        };
    }

    pub fn toJson(self: *const NewJustificationEvent, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("root", json.Value{ .string = self.root });
        try obj.put("justified_slot", json.Value{ .integer = @as(i64, @intCast(self.justified_slot)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const NewJustificationEvent, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer json_value.object.deinit();
        return jsonToString(allocator, json_value);
    }

    pub fn deinit(self: *NewJustificationEvent, allocator: Allocator) void {
        allocator.free(self.root);
    }
};

/// New finalization event data
pub const NewFinalizationEvent = struct {
    slot: u64,
    root: []const u8,
    finalized_slot: u64,

    pub fn fromCheckpoint(allocator: Allocator, checkpoint: Checkpoint, current_slot: u64) !NewFinalizationEvent {
        const root_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&checkpoint.root)});

        return NewFinalizationEvent{
            .slot = current_slot,
            .root = root_hex,
            .finalized_slot = checkpoint.slot,
        };
    }

    pub fn toJson(self: *const NewFinalizationEvent, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("root", json.Value{ .string = self.root });
        try obj.put("finalized_slot", json.Value{ .integer = @as(i64, @intCast(self.finalized_slot)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const NewFinalizationEvent, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer json_value.object.deinit();
        return jsonToString(allocator, json_value);
    }

    pub fn deinit(self: *NewFinalizationEvent, allocator: Allocator) void {
        allocator.free(self.root);
    }
};

/// Union type for all chain events
pub const ChainEvent = union(ChainEventType) {
    new_head: NewHeadEvent,
    new_justification: NewJustificationEvent,
    new_finalization: NewFinalizationEvent,

    pub fn deinit(self: *ChainEvent, allocator: Allocator) void {
        switch (self.*) {
            .new_head => |*event| event.deinit(allocator),
            .new_justification => |*event| event.deinit(allocator),
            .new_finalization => |*event| event.deinit(allocator),
        }
    }
};

/// Serialize a chain event to JSON for SSE
pub fn serializeEventToJson(allocator: Allocator, event: ChainEvent) ![]u8 {
    const event_name = @tagName(std.meta.activeTag(event));

    var json_str = std.ArrayListUnmanaged(u8){};
    defer json_str.deinit(allocator);

    // Format as SSE event
    try json_str.appendSlice(allocator, "event: ");
    try json_str.appendSlice(allocator, event_name);
    try json_str.appendSlice(allocator, "\ndata: ");

    // Serialize the data based on event type
    switch (event) {
        .new_head => |head_event| {
            const data_str = try head_event.toJsonString(allocator);
            defer allocator.free(data_str);
            try json_str.appendSlice(allocator, data_str);
        },
        .new_justification => |just_event| {
            const data_str = try just_event.toJsonString(allocator);
            defer allocator.free(data_str);
            try json_str.appendSlice(allocator, data_str);
        },
        .new_finalization => |final_event| {
            const data_str = try final_event.toJsonString(allocator);
            defer allocator.free(data_str);
            try json_str.appendSlice(allocator, data_str);
        },
    }

    try json_str.appendSlice(allocator, "\n\n");

    return json_str.toOwnedSlice(allocator);
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

    const checkpoint = Checkpoint{
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

    const checkpoint = Checkpoint{
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
