const std = @import("std");
const JsonValue = std.json.Value;

pub const Context = struct {
    fixture_label: []const u8,
    case_name: []const u8,
    step_index: ?usize = null,

    pub fn withStep(self: Context, step: ?usize) Context {
        return Context{
            .fixture_label = self.fixture_label,
            .case_name = self.case_name,
            .step_index = step,
        };
    }

    pub fn formatStep(self: Context) StepSuffix {
        return StepSuffix{ .step = self.step_index };
    }
};

pub const StepSuffix = struct {
    step: ?usize,

    pub fn format(self: StepSuffix, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        if (self.step) |idx| {
            try writer.print(" step #{}", .{idx});
        }
    }
};

fn getField(obj: std.json.ObjectMap, field_names: []const []const u8) ?JsonValue {
    for (field_names) |name| {
        if (obj.get(name)) |value| return value;
    }
    return null;
}

pub fn expectObject(
    comptime FixtureError: type,
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    context: Context,
    label: []const u8,
) FixtureError!std.json.ObjectMap {
    const value = getField(obj, field_names) orelse {
        std.debug.print(
            "fixture {s} case {s}{any}: missing field {s}\n",
            .{ context.fixture_label, context.case_name, context.formatStep(), label },
        );
        return FixtureError.InvalidFixture;
    };
    return switch (value) {
        .object => |map| map,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: field {s} must be object\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label },
            );
            return FixtureError.InvalidFixture;
        },
    };
}

pub fn expectStringField(
    comptime FixtureError: type,
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    context: Context,
    label: []const u8,
) FixtureError![]const u8 {
    const value = getField(obj, field_names) orelse {
        std.debug.print(
            "fixture {s} case {s}{any}: missing field {s}\n",
            .{ context.fixture_label, context.case_name, context.formatStep(), label },
        );
        return FixtureError.InvalidFixture;
    };
    return expectStringValue(FixtureError, value, context, label);
}

pub fn expectU64Field(
    comptime FixtureError: type,
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    context: Context,
    label: []const u8,
) FixtureError!u64 {
    const value = getField(obj, field_names) orelse {
        std.debug.print(
            "fixture {s} case {s}{any}: missing field {s}\n",
            .{ context.fixture_label, context.case_name, context.formatStep(), label },
        );
        return FixtureError.InvalidFixture;
    };
    return expectU64Value(FixtureError, value, context, label);
}

pub fn expectBytesField(
    comptime FixtureError: type,
    comptime T: type,
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    context: Context,
    label: []const u8,
) FixtureError!T {
    const value = getField(obj, field_names) orelse {
        std.debug.print(
            "fixture {s} case {s}{any}: missing hex field {s}\n",
            .{ context.fixture_label, context.case_name, context.formatStep(), label },
        );
        return FixtureError.InvalidFixture;
    };
    return expectBytesValue(FixtureError, T, value, context, label);
}

pub fn expectStringValue(
    comptime FixtureError: type,
    value: JsonValue,
    context: Context,
    label: []const u8,
) FixtureError![]const u8 {
    return switch (value) {
        .string => |s| s,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: field {s} must be string\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label },
            );
            return FixtureError.InvalidFixture;
        },
    };
}

pub fn expectU64Value(
    comptime FixtureError: type,
    value: JsonValue,
    context: Context,
    label: []const u8,
) FixtureError!u64 {
    return switch (value) {
        .integer => |i| if (i >= 0) @as(u64, @intCast(i)) else blk: {
            std.debug.print(
                "fixture {s} case {s}{any}: field {s} negative\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label },
            );
            break :blk FixtureError.InvalidFixture;
        },
        .float => {
            std.debug.print(
                "fixture {s} case {s}{any}: field {s} must be integer\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label },
            );
            return FixtureError.InvalidFixture;
        },
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: field {s} must be numeric\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label },
            );
            return FixtureError.InvalidFixture;
        },
    };
}

pub fn expectBytesValue(
    comptime FixtureError: type,
    comptime T: type,
    value: JsonValue,
    context: Context,
    label: []const u8,
) FixtureError!T {
    comptime {
        const info = @typeInfo(T);
        if (info != .array or info.array.child != u8) {
            @compileError("expectBytesValue requires an array-of-u8 type");
        }
    }

    const text = try expectStringValue(FixtureError, value, context, label);
    if (text.len < 2 or !std.mem.eql(u8, text[0..2], "0x")) {
        std.debug.print(
            "fixture {s} case {s}{any}: field {s} missing 0x prefix\n",
            .{ context.fixture_label, context.case_name, context.formatStep(), label },
        );
        return FixtureError.InvalidFixture;
    }

    const body = text[2..];
    const expected_len = comptime (@typeInfo(T).array.len * 2);
    if (body.len != expected_len) {
        std.debug.print(
            "fixture {s} case {s}{any}: field {s} wrong length\n",
            .{ context.fixture_label, context.case_name, context.formatStep(), label },
        );
        return FixtureError.InvalidFixture;
    }

    var out: T = undefined;
    _ = std.fmt.hexToBytes(&out, body) catch {
        std.debug.print(
            "fixture {s} case {s}{any}: field {s} invalid hex\n",
            .{ context.fixture_label, context.case_name, context.formatStep(), label },
        );
        return FixtureError.InvalidFixture;
    };
    return out;
}

pub fn expectObjectValue(
    comptime FixtureError: type,
    value: JsonValue,
    context: Context,
    label: []const u8,
) FixtureError!std.json.ObjectMap {
    return switch (value) {
        .object => |map| map,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: field {s} must be object\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label },
            );
            return FixtureError.InvalidFixture;
        },
    };
}

pub fn expectArrayValue(
    comptime FixtureError: type,
    value: JsonValue,
    context: Context,
    label: []const u8,
) FixtureError!std.json.Array {
    return switch (value) {
        .array => |arr| arr,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: field {s} must be array\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label },
            );
            return FixtureError.InvalidFixture;
        },
    };
}

pub fn appendBytesDataField(
    comptime FixtureError: type,
    comptime T: type,
    list: anytype,
    context: Context,
    container: JsonValue,
    label: []const u8,
) FixtureError!void {
    const obj = try expectObjectValue(FixtureError, container, context, label);
    const data_val = obj.get("data") orelse return;
    const arr = switch (data_val) {
        .array => |array| array,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: {s}.data must be array\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label },
            );
            return FixtureError.InvalidFixture;
        },
    };

    for (arr.items) |item| {
        const value = try expectBytesValue(FixtureError, T, item, context, label);
        list.append(value) catch |err| {
            std.debug.print(
                "fixture {s} case {s}{any}: {s} append failed: {s}\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label, @errorName(err) },
            );
            return FixtureError.InvalidFixture;
        };
    }
}

pub fn appendBoolDataField(
    comptime FixtureError: type,
    list: anytype,
    context: Context,
    container: JsonValue,
    label: []const u8,
) FixtureError!void {
    const obj = try expectObjectValue(FixtureError, container, context, label);
    const data_val = obj.get("data") orelse return;
    const arr = switch (data_val) {
        .array => |array| array,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: {s}.data must be array\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label },
            );
            return FixtureError.InvalidFixture;
        },
    };

    for (arr.items) |item| {
        const flag = switch (item) {
            .bool => |b| b,
            .integer => |ival| ival != 0,
            else => {
                std.debug.print(
                    "fixture {s} case {s}{any}: {s} entries must be bool/int\n",
                    .{ context.fixture_label, context.case_name, context.formatStep(), label },
                );
                return FixtureError.InvalidFixture;
            },
        };
        list.append(flag) catch |err| {
            std.debug.print(
                "fixture {s} case {s}{any}: {s} append failed: {s}\n",
                .{ context.fixture_label, context.case_name, context.formatStep(), label, @errorName(err) },
            );
            return FixtureError.InvalidFixture;
        };
    }
}
