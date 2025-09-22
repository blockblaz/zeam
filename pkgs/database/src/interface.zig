const rocksdb = @import("rocksdb");
const std = @import("std");

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

    pub fn Entry(self: Self) type {
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

    std.debug.assert(cn[0].find(&cn) == 0);
    std.debug.assert(cn[1].find(&cn) == 1);
    std.debug.assert(cn[2].find(&cn) == 2);
}
