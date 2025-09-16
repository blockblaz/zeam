const std = @import("std");
const Allocator = std.mem.Allocator;
const fcFactory = @import("./forkchoice.zig");

/// Builds a tree visualization of the fork choice tree with optional depth limit
pub fn buildTreeVisualization(allocator: Allocator, nodes: []const fcFactory.ProtoNode, max_depth: ?usize) ![]const u8 {
    var tree_lines = std.ArrayList(u8).init(allocator);
    defer tree_lines.deinit();

    // Find root nodes (nodes with no parent)
    var root_indices = std.ArrayList(usize).init(allocator);
    defer root_indices.deinit();

    for (nodes, 0..) |node, i| {
        if (node.parent == null) {
            try root_indices.append(i);
        }
    }

    // Build tree visualization starting from roots
    for (root_indices.items) |root_idx| {
        try visualizeTreeBranch(allocator, &tree_lines, nodes, root_idx, 0, "", max_depth);
    }

    return tree_lines.toOwnedSlice();
}

/// Recursively builds a tree branch visualization
fn visualizeTreeBranch(allocator: Allocator, tree_lines: *std.ArrayList(u8), nodes: []const fcFactory.ProtoNode, node_idx: usize, depth: usize, prefix: []const u8, max_depth: ?usize) !void {
    const node = nodes[node_idx];
    const hex_root = std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(node.blockRoot[0..4])}) catch "0x????";
    defer allocator.free(hex_root);

    const node_line = std.fmt.allocPrint(allocator, "{s}{s} ({d})", .{ prefix, hex_root, node.slot }) catch return;
    defer allocator.free(node_line);

    try tree_lines.appendSlice(node_line);

    // Check if we've reached the maximum depth
    if (max_depth) |max| {
        if (depth >= max) {
            const truncated_comment = std.fmt.allocPrint(allocator, " // ... (truncated at depth {d})", .{max}) catch return;
            defer allocator.free(truncated_comment);
            try tree_lines.appendSlice(truncated_comment);
            try tree_lines.append('\n');
            return;
        }
    }

    var children = std.ArrayList(usize).init(allocator);
    defer children.deinit();

    for (nodes, 0..) |child_node, i| {
        if (child_node.parent) |parent_idx| {
            if (parent_idx == node_idx) {
                try children.append(i);
            }
        }
    }

    if (children.items.len > 0) {
        const child_count_comment = std.fmt.allocPrint(allocator, " // has {d} child branch{s}", .{ children.items.len, if (children.items.len == 1) "" else "es" }) catch return;
        defer allocator.free(child_count_comment);
        try tree_lines.appendSlice(child_count_comment);
    }
    try tree_lines.append('\n');

    for (children.items, 0..) |child_idx, child_i| {
        const child_node = nodes[child_idx];
        const is_last_child = child_i == children.items.len - 1;

        const indent = createTreeIndent(allocator, depth, is_last_child) catch return;
        defer allocator.free(indent);

        // Check for missing slots between parent and child
        if (child_node.slot > node.slot + 1) {
            const missing_line = std.fmt.allocPrint(allocator, "{s}[slots {d}..{d}] ─┘ ", .{ indent, node.slot + 1, child_node.slot - 1 }) catch return;
            defer allocator.free(missing_line);
            try tree_lines.appendSlice(missing_line);
        } else {
            try tree_lines.appendSlice(indent);
        }

        // Recursively process child
        try visualizeTreeBranch(allocator, tree_lines, nodes, child_idx, depth + 1, "", max_depth);
    }
}

/// Helper function to create proper tree indentation
fn createTreeIndent(allocator: Allocator, depth: usize, is_last_child: bool) ![]const u8 {
    var indent = std.ArrayList(u8).init(allocator);
    defer indent.deinit();

    // Add indentation for each depth level
    for (0..depth) |_| {
        try indent.appendSlice("    ");
    }

    // Add tree characters based on position
    const tree_char = if (is_last_child) "└── " else "├── ";
    try indent.appendSlice(tree_char);

    return indent.toOwnedSlice();
}

