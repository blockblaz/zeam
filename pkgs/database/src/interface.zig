const rocksdb = @import("rocksdb");
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");

/// Helper function to format block keys consistently
pub fn formatBlockKey(allocator: Allocator, block_root: types.Root) ![]const u8 {
    return std.fmt.allocPrint(allocator, "block:{any}", .{std.fmt.fmtSliceHexLower(&block_root)});
}

/// Helper function to format state keys consistently
pub fn formatStateKey(allocator: Allocator, state_root: types.Root) ![]const u8 {
    return std.fmt.allocPrint(allocator, "state:{any}", .{std.fmt.fmtSliceHexLower(&state_root)});
}

/// Helper function to format finalized slot index keys
pub fn formatFinalizedSlotKey(allocator: Allocator, slot: types.Slot) ![]const u8 {
    return std.fmt.allocPrint(allocator, "finalized_slot_{d}", .{slot});
}

/// Helper function to format unfinalized slot index keys
pub fn formatUnfinalizedSlotKey(allocator: Allocator, slot: types.Slot) ![]const u8 {
    return std.fmt.allocPrint(allocator, "unfinalized_slot_{d}", .{slot});
}

/// Gets the return type of a function or function pointer
pub fn ReturnType(comptime FnPtr: type) type {
    return switch (@typeInfo(FnPtr)) {
        .@"fn" => |fun| fun.return_type.?,
        .pointer => |ptr| @typeInfo(ptr.child).@"fn".return_type.?,
        else => @compileError("not a function or function pointer"),
    };
}

/// A namespace for a column
/// Can be used to iterate over a column
/// and to find the index of a column family in a slice
pub const ColumnNamespace = struct {
    namespace: []const u8,
    Key: type,
    Value: type,

    const Self = @This();

    pub fn Entry(comptime self: Self) type {
        return struct { self.Key, self.Value };
    }

    /// At comptime, find this family in a slice. Useful for for fast runtime
    /// accesses of data in other slices that are one-to-one with this slice.
    pub fn find(comptime self: Self, comptime column_namespaces: []const Self) comptime_int {
        for (column_namespaces, 0..) |column_namespace, i| {
            if (std.mem.eql(u8, column_namespace.namespace, self.namespace)) {
                return i;
            }
        }
        @compileError("not found");
    }
};

pub const IteratorDirection = enum { forward, reverse };

test "verify_find_function_for_column_namespaces" {
    const cn = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = u8, .Value = u8 },
        .{ .namespace = "cn1", .Key = u8, .Value = u8 },
        .{ .namespace = "cn2", .Key = u8, .Value = u8 },
    };

    try std.testing.expectEqual(@as(comptime_int, 0), cn[0].find(&cn));
    try std.testing.expectEqual(@as(comptime_int, 1), cn[1].find(&cn));
    try std.testing.expectEqual(@as(comptime_int, 2), cn[2].find(&cn));
}
