const std = @import("std");

const Allocator = std.mem.Allocator;

/// Returns true when `T` can be cloned with a direct value copy.
/// Types with custom clone methods return false so their methods are honored.
/// Unsupported type kinds return false conservatively.
pub fn hasNoPointers(T: type) bool {
    if (comptime std.meta.hasFn(T, "clone")) return false;

    return switch (@typeInfo(T)) {
        .int, .bool, .float, .void, .null, .@"enum" => true,
        .array => |array| hasNoPointers(array.child),
        .vector => |vector| hasNoPointers(vector.child),
        .optional => |optional| hasNoPointers(optional.child),
        .@"struct" => |str| blk: {
            inline for (str.fields) |field| {
                if (field.is_comptime) continue;
                if (!hasNoPointers(field.type)) break :blk false;
            }
            break :blk true;
        },
        .@"union" => |un| blk: {
            if (un.tag_type == null) break :blk false;
            inline for (un.fields) |field| {
                if (!hasNoPointers(field.type)) break :blk false;
            }
            break :blk true;
        },
        else => false,
    };
}

fn cleanupClone(T: type, data: T, allocator: Allocator) void {
    if (comptime std.meta.hasFn(T, "deinit")) {
        var clone_data = data;
        clone_data.deinit();
        return;
    }
    if (comptime hasNoPointers(T)) return;

    switch (@typeInfo(T)) {
        .int, .bool, .float, .null, .@"enum" => {},
        .array => |array| {
            if (comptime !hasNoPointers(array.child)) {
                for (data) |item| cleanupClone(array.child, item, allocator);
            }
        },
        .optional => |optional| {
            if (data) |value| cleanupClone(optional.child, value, allocator);
        },
        .pointer => |ptr| switch (ptr.size) {
            .slice => {
                if (comptime ptr.is_const and @sizeOf(ptr.child) == 1) return;
                if (comptime !hasNoPointers(ptr.child)) {
                    for (data) |item| cleanupClone(ptr.child, item, allocator);
                }
                allocator.free(data);
            },
            .one => {
                cleanupClone(ptr.child, data.*, allocator);
                const alignment = comptime ptr.alignment orelse @alignOf(ptr.child);
                if (comptime alignment == @alignOf(ptr.child)) {
                    allocator.destroy(@constCast(data));
                } else {
                    const slice: []align(alignment) ptr.child = @as([*]align(alignment) ptr.child, @ptrCast(@constCast(data)))[0..1];
                    allocator.free(slice);
                }
            },
            else => @compileError("clone cleanup does not support " ++ @tagName(ptr.size) ++ " pointers"),
        },
        .@"struct" => |str| {
            inline for (str.fields) |field| {
                if (field.is_comptime) continue;
                cleanupClone(field.type, @field(data, field.name), allocator);
            }
        },
        .@"union" => |un| {
            if (un.tag_type == null) @compileError("clone cleanup does not support untagged unions");
            switch (data) {
                inline else => |payload| cleanupClone(@TypeOf(payload), payload, allocator),
            }
        },
        else => {},
    }
}

/// Clones `data` and returns the cloned value.
/// Cloned values follow the same cleanup model as their source:
/// containers use `deinit`, allocated slices use `allocator.free`, and
/// const slices of byte-sized scalars (`[]const u8`, etc.) remain borrowed.
/// Types providing a `clone` method must also provide `deinit`; partial-failure
/// unwinds rely on `deinit` to release whatever the hook allocated.
/// Returns `error.AllocatorRequired` when `allocator` is null but the value
/// has owned heap data (mutable slices, single pointers, or `clone` hooks).
pub fn clone(T: type, data: *const T, allocator: ?Allocator) !T {
    if (comptime std.meta.hasFn(T, "clone")) {
        if (comptime !std.meta.hasFn(T, "deinit")) {
            @compileError("type " ++ @typeName(T) ++ " provides clone but no deinit; cleanup on partial clone failure would be undefined");
        }
        const alloc = allocator orelse return error.AllocatorRequired;
        return data.clone(alloc);
    }
    if (comptime hasNoPointers(T)) return data.*;

    switch (@typeInfo(T)) {
        .int, .bool, .float, .void, .null, .@"enum" => return data.*,
        .array => |array| {
            var result: T = undefined;
            var done: usize = 0;
            errdefer if (allocator) |alloc| {
                for (result[0..done]) |item| cleanupClone(array.child, item, alloc);
            };
            while (done < data.len) : (done += 1) {
                result[done] = try clone(array.child, &data[done], allocator);
            }
            return result;
        },
        .optional => |optional| {
            if (data.* == null) return null;
            return try clone(optional.child, &data.*.?, allocator);
        },
        .pointer => |ptr| switch (ptr.size) {
            .slice => {
                if (comptime ptr.is_const and @sizeOf(ptr.child) == 1) return data.*;
                const alloc = allocator orelse return error.AllocatorRequired;
                const alignment: std.mem.Alignment = comptime .fromByteUnits(ptr.alignment orelse @alignOf(ptr.child));
                const sentinel = comptime ptr.sentinel();
                const out = try alloc.allocWithOptions(ptr.child, data.len, alignment, sentinel);
                errdefer alloc.free(out);
                if (comptime hasNoPointers(ptr.child)) {
                    @memcpy(out, data.*);
                } else {
                    var done: usize = 0;
                    errdefer for (out[0..done]) |item| cleanupClone(ptr.child, item, alloc);
                    while (done < data.len) : (done += 1) {
                        out[done] = try clone(ptr.child, &data.*[done], allocator);
                    }
                }
                return out;
            },
            .one => {
                const alloc = allocator orelse return error.AllocatorRequired;
                const alignment = comptime ptr.alignment orelse @alignOf(ptr.child);
                if (comptime alignment == @alignOf(ptr.child)) {
                    const slot = try alloc.create(ptr.child);
                    errdefer alloc.destroy(slot);
                    slot.* = try clone(ptr.child, data.*, allocator);
                    return slot;
                } else {
                    const alloc_alignment: std.mem.Alignment = comptime .fromByteUnits(alignment);
                    const slot = try alloc.allocWithOptions(ptr.child, 1, alloc_alignment, null);
                    errdefer alloc.free(slot);
                    slot[0] = try clone(ptr.child, data.*, allocator);
                    return &slot[0];
                }
            },
            else => return error.UnSupportedPointerType,
        },
        .@"struct" => |str| {
            var result: T = undefined;
            var fields_done: usize = 0;
            errdefer if (allocator) |alloc| {
                var seen: usize = 0;
                inline for (str.fields) |field| {
                    if (field.is_comptime) continue;
                    if (seen >= fields_done) break;
                    cleanupClone(field.type, @field(result, field.name), alloc);
                    seen += 1;
                }
            };
            inline for (str.fields) |field| {
                if (field.is_comptime) continue;
                @field(result, field.name) = try clone(field.type, &@field(data, field.name), allocator);
                fields_done += 1;
            }
            return result;
        },
        .@"union" => |un| {
            if (un.tag_type == null) @compileError("clone does not support untagged unions");
            switch (data.*) {
                inline else => |payload, tag| {
                    const payload_clone = try clone(@TypeOf(payload), &payload, allocator);
                    return @unionInit(T, @tagName(tag), payload_clone);
                },
            }
        },
        else => return error.NotImplemented,
    }
}

const expect = std.testing.expect;
const expectError = std.testing.expectError;

test "clone: pointer-free value works without allocator" {
    const S = struct {
        n: u32,
        bytes: [4]u8,
        tag: enum { a, b },
    };
    const data = S{ .n = 42, .bytes = .{ 1, 2, 3, 4 }, .tag = .b };

    const cloned = try clone(S, &data, null);

    try expect(hasNoPointers(S));
    try expect(std.meta.eql(data, cloned));
}

test "clone: const byte slice is borrowed without allocator" {
    const data: []const u8 = "hello";

    const cloned = try clone([]const u8, &data, null);

    try expect(std.mem.eql(u8, cloned, data));
    try expect(cloned.ptr == data.ptr);
}

test "clone: mutable slice requires allocator" {
    const data = try std.testing.allocator.dupe(u8, "hello");
    defer std.testing.allocator.free(data);

    try expectError(error.AllocatorRequired, clone([]u8, &data, null));
}

test "clone: mutable slice copy is independent" {
    const data = try std.testing.allocator.dupe(u8, "hello");
    defer std.testing.allocator.free(data);

    const cloned = try clone([]u8, &data, std.testing.allocator);
    defer std.testing.allocator.free(cloned);

    cloned[0] = 'H';
    try expect(data[0] == 'h');
    try expect(std.mem.eql(u8, cloned, "Hello"));
}

test "clone: struct follows normal slice cleanup ownership" {
    const S = struct {
        a: []u8,
        b: []const u8,
    };
    const a = try std.testing.allocator.dupe(u8, "left");
    defer std.testing.allocator.free(a);
    const data = S{ .a = a, .b = "right" };

    const cloned = try clone(S, &data, std.testing.allocator);
    defer std.testing.allocator.free(cloned.a);

    try expect(std.mem.eql(u8, cloned.a, data.a));
    try expect(std.mem.eql(u8, cloned.b, data.b));
    try expect(cloned.a.ptr != data.a.ptr);
    try expect(cloned.b.ptr == data.b.ptr);
}

test "clone: single pointer is deep-copied" {
    var value: u32 = 123;
    const data: *u32 = &value;

    const cloned = try clone(*u32, &data, std.testing.allocator);
    defer std.testing.allocator.destroy(cloned);

    try expect(cloned != data);
    try expect(cloned.* == data.*);
    cloned.* = 456;
    try expect(value == 123);
}

test "clone: const single pointer is deep-copied" {
    const value: u32 = 123;
    const data: *const u32 = &value;

    const cloned = try clone(*const u32, &data, std.testing.allocator);
    defer std.testing.allocator.destroy(@constCast(cloned));

    try expect(cloned != data);
    try expect(cloned.* == data.*);
}

test "clone: over-aligned single pointer preserves alignment" {
    const data = try std.testing.allocator.alignedAlloc(u32, .fromByteUnits(16), 1);
    defer std.testing.allocator.free(data);
    data[0] = 0xcafebabe;
    const ptr: *align(16) u32 = &data[0];

    const cloned = try clone(*align(16) u32, &ptr, std.testing.allocator);
    defer {
        const cloned_slice: []align(16) u32 = @as([*]align(16) u32, @ptrCast(cloned))[0..1];
        std.testing.allocator.free(cloned_slice);
    }

    try expect(cloned != ptr);
    try expect(cloned.* == ptr.*);
    try expect(@intFromPtr(cloned) % 16 == 0);
}

test "clone: optional pointer" {
    var value: u32 = 99;
    const some: ?*u32 = &value;

    const cloned_some = try clone(?*u32, &some, std.testing.allocator);
    defer if (cloned_some) |ptr| std.testing.allocator.destroy(ptr);
    const none_value: ?*u32 = null;
    const cloned_none = try clone(?*u32, &none_value, null);

    try expect(cloned_some.?.* == 99);
    try expect(cloned_some.? != some.?);
    try expect(cloned_none == null);
}

test "clone: sentinel-terminated slice preserves sentinel" {
    const data = try std.testing.allocator.dupeZ(u8, "hello");
    defer std.testing.allocator.free(data);

    const cloned = try clone([:0]u8, &data, std.testing.allocator);
    defer std.testing.allocator.free(cloned);

    try expect(std.mem.eql(u8, cloned, data));
    try expect(cloned.ptr != data.ptr);
    try expect(cloned[cloned.len] == 0);
}

test "clone: struct unwind frees earlier fields when later allocation fails" {
    const S = struct {
        a: []u8,
        b: []u8,
    };
    const a = try std.testing.allocator.dupe(u8, "first");
    defer std.testing.allocator.free(a);
    const b = try std.testing.allocator.dupe(u8, "second");
    defer std.testing.allocator.free(b);
    const data = S{ .a = a, .b = b };

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    try expectError(error.OutOfMemory, clone(S, &data, failing.allocator()));
}

test "clone: array of const byte slices keeps borrowed items" {
    const data: [3][]const u8 = .{ "one", "two", "three" };

    const cloned = try clone([3][]const u8, &data, null);

    inline for (0..3) |i| {
        try expect(std.mem.eql(u8, cloned[i], data[i]));
        try expect(cloned[i].ptr == data[i].ptr);
    }
}

test "clone: tagged union active variant follows slice ownership" {
    const Payload = union(enum) {
        bytes: []const u8,
        n: u32,
    };

    const bytes_value = Payload{ .bytes = "abc" };
    const cloned_bytes = try clone(Payload, &bytes_value, std.testing.allocator);
    try expect(std.mem.eql(u8, cloned_bytes.bytes, "abc"));
    try expect(cloned_bytes.bytes.ptr == @as([]const u8, "abc").ptr);

    const n_value = Payload{ .n = 7 };
    const cloned_n = try clone(Payload, &n_value, null);
    try expect(cloned_n.n == 7);
}

test "clone: tagged union unwind frees payload when nested allocation fails" {
    const Payload = union(enum) {
        pair: struct {
            a: []u8,
            b: []u8,
        },
        n: u32,
    };
    const a = try std.testing.allocator.dupe(u8, "first");
    defer std.testing.allocator.free(a);
    const b = try std.testing.allocator.dupe(u8, "second");
    defer std.testing.allocator.free(b);
    const data = Payload{ .pair = .{ .a = a, .b = b } };

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    try expectError(error.OutOfMemory, clone(Payload, &data, failing.allocator()));
}

test "clone: dispatches to user-defined clone hook" {
    const Buf = struct {
        const Self = @This();
        items: []u8,
        allocator: Allocator,

        pub fn clone(self: *const Self, allocator: Allocator) !Self {
            const items = try allocator.dupe(u8, self.items);
            return .{ .items = items, .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.items);
        }
    };

    const items = try std.testing.allocator.dupe(u8, "abc");
    var data = Buf{ .items = items, .allocator = std.testing.allocator };
    defer data.deinit();

    var cloned = try clone(Buf, &data, std.testing.allocator);
    defer cloned.deinit();

    try expect(std.mem.eql(u8, cloned.items, data.items));
    try expect(cloned.items.ptr != data.items.ptr);
}

test "clone: hook requires allocator" {
    const Buf = struct {
        const Self = @This();
        pub fn clone(_: *const Self, _: Allocator) !Self {
            return .{};
        }
        pub fn deinit(_: *Self) void {}
    };

    const empty_buf = Buf{};
    try expectError(error.AllocatorRequired, clone(Buf, &empty_buf, null));
}

// Mirrors ssz.utils.List's clone-hook contract so this test exercises the
// orchestrator's variable-type-list path without requiring the lyon-v1 ssz
// dependency to include PR #64. The shape (`inner: ArrayList`, `init`,
// `append`, `deinit`, `clone`) matches ssz.utils.List item-for-item, so the
// orchestrator behaviour validated here transfers directly once the dep is
// bumped.
fn StubList(comptime Item: type) type {
    return struct {
        const Self = @This();
        inner: std.ArrayList(Item),
        allocator: Allocator,

        pub fn init(allocator: Allocator) !Self {
            return .{ .inner = .empty, .allocator = allocator };
        }

        pub fn append(self: *Self, item: Item) !void {
            try self.inner.append(self.allocator, item);
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit(self.allocator);
        }

        pub fn clone(self: *const Self, allocator: Allocator) !Self {
            var cloned = try Self.init(allocator);
            errdefer cloned.deinit();
            try cloned.inner.appendSlice(allocator, self.inner.items);
            return cloned;
        }
    };
}

test "clone: List-like container with variable-typed items" {
    const L = StubList([]const u8);
    var data = try L.init(std.testing.allocator);
    defer data.deinit();
    try data.append("aa");
    try data.append("bbbb");
    try data.append("ccccccc");

    var cloned = try clone(L, &data, std.testing.allocator);
    defer cloned.deinit();

    try expect(cloned.inner.items.len == data.inner.items.len);
    // Spine reallocated independently of the source.
    try expect(cloned.inner.items.ptr != data.inner.items.ptr);
    // Variable-sized items are borrowed (shallow item copy), matching how
    // ssz.utils.List.clone forwards items via appendSlice.
    inline for (0..3) |i| {
        try expect(std.mem.eql(u8, cloned.inner.items[i], data.inner.items[i]));
        try expect(cloned.inner.items[i].ptr == data.inner.items[i].ptr);
    }
}

test "clone: List-like container of variable-sized structs" {
    const Pastry = struct {
        name: []const u8,
        weight: u16,
    };
    const L = StubList(Pastry);

    var data = try L.init(std.testing.allocator);
    defer data.deinit();
    try data.append(.{ .name = "croissant", .weight = 20 });
    try data.append(.{ .name = "Herrentorte", .weight = 500 });

    var cloned = try clone(L, &data, std.testing.allocator);
    defer cloned.deinit();

    try expect(cloned.inner.items.len == 2);
    try expect(cloned.inner.items.ptr != data.inner.items.ptr);
    try expect(cloned.inner.items[0].weight == 20);
    try expect(cloned.inner.items[1].weight == 500);
    // The struct items hold a borrowed []const u8; the shallow item copy
    // keeps the same name pointer.
    try expect(cloned.inner.items[0].name.ptr == data.inner.items[0].name.ptr);
    try expect(cloned.inner.items[1].name.ptr == data.inner.items[1].name.ptr);
}

test "clone: struct containing a List-like field of variable items" {
    const L = StubList([]const u8);
    const S = struct {
        names: L,
        label: []const u8,
        payload: []u8,
        version: u32,
    };

    const allocator = std.testing.allocator;

    var names = try L.init(allocator);
    defer names.deinit();
    try names.append("alpha");
    try names.append("beta");

    const payload = try allocator.dupe(u8, "owned");
    defer allocator.free(payload);

    const data = S{
        .names = names,
        .label = "hello",
        .payload = payload,
        .version = 7,
    };

    var cloned = try clone(S, &data, allocator);
    defer {
        cloned.names.deinit();
        allocator.free(cloned.payload);
    }

    try expect(cloned.version == 7);
    // Borrowed slice stays borrowed.
    try expect(cloned.label.ptr == data.label.ptr);
    // Owned slice is independent.
    try expect(cloned.payload.ptr != data.payload.ptr);
    cloned.payload[0] = 'X';
    try expect(data.payload[0] == 'o');
    // List hook ran: spine independent, items borrowed.
    try expect(cloned.names.inner.items.ptr != data.names.inner.items.ptr);
    try expect(cloned.names.inner.items[0].ptr == data.names.inner.items[0].ptr);
}

test "clone: struct with List-like field unwinds when later allocation fails" {
    const L = StubList([]const u8);
    const S = struct {
        names: L,
        payload: []u8,
    };

    const allocator = std.testing.allocator;

    var names = try L.init(allocator);
    defer names.deinit();
    try names.append("alpha");

    const payload = try allocator.dupe(u8, "owned");
    defer allocator.free(payload);

    var data = S{ .names = names, .payload = payload };

    // Index 0 is the List's inner buffer; index 1 (the []u8) is forced to fail.
    // The struct errdefer should deinit the cloned list so we don't leak.
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    try expectError(error.OutOfMemory, clone(S, &data, failing.allocator()));
}
