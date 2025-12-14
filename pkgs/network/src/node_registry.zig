const std = @import("std");
const Allocator = std.mem.Allocator;
const zeam_utils = @import("@zeam/utils");

/// A registry that maps peer IDs and validator indices to node names
/// for better log readability and debugging
pub const NodeNameRegistry = struct {
    allocator: Allocator,
    peer_id_to_name: std.StringHashMap([]const u8),
    validator_index_to_name: std.AutoHashMap(usize, []const u8),

    pub fn init(allocator: Allocator) NodeNameRegistry {
        return .{
            .allocator = allocator,
            .peer_id_to_name = std.StringHashMap([]const u8).init(allocator),
            .validator_index_to_name = std.AutoHashMap(usize, []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *NodeNameRegistry) void {
        // Free all keys and values in peer_id_to_name
        var peer_it = self.peer_id_to_name.iterator();
        while (peer_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.peer_id_to_name.deinit();

        // Free all values in validator_index_to_name (keys are usize, don't need freeing)
        var val_it = self.validator_index_to_name.iterator();
        while (val_it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.validator_index_to_name.deinit();
    }

    /// Add a mapping from peer ID to node name
    pub fn addPeerMapping(self: *NodeNameRegistry, peer_id: []const u8, node_name: []const u8) !void {
        const peer_id_copy = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(peer_id_copy);
        const node_name_copy = try self.allocator.dupe(u8, node_name);
        errdefer self.allocator.free(node_name_copy);

        // Check if we're overwriting an existing entry and free the old values
        const result = try self.peer_id_to_name.fetchPut(peer_id_copy, node_name_copy);
        if (result) |old_entry| {
            self.allocator.free(old_entry.key);
            self.allocator.free(old_entry.value);
        }
    }

    /// Add a mapping from validator index to node name
    pub fn addValidatorMapping(self: *NodeNameRegistry, validator_index: usize, node_name: []const u8) !void {
        const node_name_copy = try self.allocator.dupe(u8, node_name);
        errdefer self.allocator.free(node_name_copy);

        // Check if we're overwriting an existing entry and free the old value
        const result = try self.validator_index_to_name.fetchPut(validator_index, node_name_copy);
        if (result) |old_entry| {
            self.allocator.free(old_entry.value);
        }
    }

    /// Get node name from peer ID, returns null if not found
    pub fn getNodeNameFromPeerId(self: *const NodeNameRegistry, peer_id: []const u8) zeam_utils.OptionalNode {
        return zeam_utils.OptionalNode.init(self.peer_id_to_name.get(peer_id));
    }

    /// Get node name from validator index, returns null if not found
    pub fn getNodeNameFromValidatorIndex(self: *const NodeNameRegistry, validator_index: usize) zeam_utils.OptionalNode {
        return zeam_utils.OptionalNode.init(self.validator_index_to_name.get(validator_index));
    }
};

test "NodeNameRegistry tests" {
    const allocator = std.testing.allocator;

    var registry = NodeNameRegistry.init(allocator);
    defer registry.deinit();

    // Add both types of mappings
    try registry.addPeerMapping("peer_abc", "node_1");
    try registry.addValidatorMapping(10, "node_1");
    try registry.addPeerMapping("peer_def", "node_2");
    try registry.addValidatorMapping(20, "node_2");

    // Test peer mappings
    const peer1 = registry.getNodeNameFromPeerId("peer_abc");
    try std.testing.expect(peer1.name != null);
    try std.testing.expectEqualStrings("node_1", peer1.name.?);

    const peer2 = registry.getNodeNameFromPeerId("peer_def");
    try std.testing.expect(peer2.name != null);
    try std.testing.expectEqualStrings("node_2", peer2.name.?);

    // Test validator mappings
    const val1 = registry.getNodeNameFromValidatorIndex(10);
    try std.testing.expect(val1.name != null);
    try std.testing.expectEqualStrings("node_1", val1.name.?);

    const val2 = registry.getNodeNameFromValidatorIndex(20);
    try std.testing.expect(val2.name != null);
    try std.testing.expectEqualStrings("node_2", val2.name.?);

    // Empty registry should return null for any query
    const peer_result = registry.getNodeNameFromPeerId("any_peer");
    try std.testing.expect(peer_result.name == null);

    const val_result = registry.getNodeNameFromValidatorIndex(0);
    try std.testing.expect(val_result.name == null);
}
