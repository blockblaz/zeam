const std = @import("std");
const Allocator = std.mem.Allocator;
const fcFactory = @import("./forkchoice.zig");

/// Builds a tree visualization of the fork choice tree with optional depth limit
pub fn buildTreeVisualization(allocator: Allocator, nodes: []const fcFactory.ProtoNode, max_depth: ?usize) ![]const u8 {
    var tree_lines = std.ArrayListUnmanaged(u8){};
    defer tree_lines.deinit(allocator);

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

    return tree_lines.toOwnedSlice(allocator);
}

/// Recursively builds a tree branch visualization
fn visualizeTreeBranch(allocator: Allocator, tree_lines: *std.ArrayListUnmanaged(u8), nodes: []const fcFactory.ProtoNode, node_idx: usize, depth: usize, prefix: []const u8, max_depth: ?usize) !void {
    const node = nodes[node_idx];
    const hex_root = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(node.blockRoot[0..2])});
    defer allocator.free(hex_root);

    const node_line = try std.fmt.allocPrint(allocator, "{s}{s}({d})", .{ prefix, hex_root, node.slot });
    defer allocator.free(node_line);

    try tree_lines.appendSlice(allocator, node_line);

    // Check if we've reached the maximum depth
    if (max_depth) |max| {
        if (depth >= max) {
            const truncated_comment = try std.fmt.allocPrint(allocator, " ... (truncated at depth {d})", .{max});
            defer allocator.free(truncated_comment);
            try tree_lines.appendSlice(allocator, truncated_comment);
            try tree_lines.append(allocator, '\n');
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
        const child_count_comment = try std.fmt.allocPrint(allocator, " has {d} child branch{s}", .{ children.items.len, if (children.items.len == 1) "" else "es" });
        defer allocator.free(child_count_comment);
        try tree_lines.appendSlice(allocator, child_count_comment);
    }
    try tree_lines.append(allocator, '\n');

    for (children.items, 0..) |child_idx, child_i| {
        const child_node = nodes[child_idx];
        const is_last_child = child_i == children.items.len - 1;

        const indent = try createTreeIndent(allocator, depth, is_last_child);
        defer allocator.free(indent);

        // Check for missing slots between parent and child
        if (child_node.slot > node.slot + 1) {
            const missing_slots = child_node.slot - node.slot - 1;
            const missing_line = if (missing_slots == 1)
                try std.fmt.allocPrint(allocator, "{s}[{d}] ─┘ ", .{ indent, node.slot + 1 })
            else
                try std.fmt.allocPrint(allocator, "{s}[{d}..{d}] ─┘ ", .{ indent, node.slot + 1, child_node.slot - 1 });
            defer allocator.free(missing_line);
            try tree_lines.appendSlice(allocator, missing_line);
        } else {
            try tree_lines.appendSlice(allocator, indent);
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

/// Build fork choice graph in Grafana node-graph JSON format
pub fn buildForkChoiceGraphJSON(
    forkchoice: *fcFactory.ForkChoice,
    writer: anytype,
    max_slots: usize,
    allocator: Allocator,
) !void {
    const snapshot = try forkchoice.snapshot(allocator);
    defer snapshot.deinit(allocator);

    const proto_nodes = snapshot.nodes;

    // Determine the slot threshold (show only recent slots)
    const current_slot = snapshot.head.slot;
    const min_slot = if (current_slot > max_slots) current_slot - max_slots else 0;

    // Build nodes and edges
    var nodes_list = std.ArrayList(u8).init(allocator);
    defer nodes_list.deinit();
    var edges_list = std.ArrayList(u8).init(allocator);
    defer edges_list.deinit();

    var node_count: usize = 0;
    var edge_count: usize = 0;

    // Find max weight for normalization
    var max_weight: isize = 1;
    for (proto_nodes) |pnode| {
        if (pnode.slot >= min_slot and pnode.weight > max_weight) {
            max_weight = pnode.weight;
        }
    }

    // Find the finalized node index to check ancestry
    const finalized_idx = blk: {
        for (proto_nodes, 0..) |n, i| {
            if (std.mem.eql(u8, &n.blockRoot, &snapshot.latest_finalized_root)) {
                break :blk i;
            }
        }
        break :blk null;
    };

    for (proto_nodes, 0..) |pnode, idx| {
        if (pnode.slot < min_slot) continue;

        // Determine node role and color
        const is_head = std.mem.eql(u8, &pnode.blockRoot, &snapshot.head.blockRoot);
        const is_justified = std.mem.eql(u8, &pnode.blockRoot, &snapshot.latest_justified_root);

        // A block is finalized if:
        // 1. It equals the finalized checkpoint, OR
        // 2. The finalized block is a descendant of it (block is ancestor of finalized)
        const is_finalized = blk: {
            // Check if this block IS the finalized block
            if (std.mem.eql(u8, &pnode.blockRoot, &snapshot.latest_finalized_root)) {
                break :blk true;
            }
            // Check if this block is an ancestor of the finalized block
            if (finalized_idx) |fin_idx| {
                var current_idx: ?usize = fin_idx;
                while (current_idx) |curr| {
                    if (curr == idx) break :blk true;
                    current_idx = proto_nodes[curr].parent;
                }
            }
            break :blk false;
        };

        // Get finalized slot for orphaned block detection
        const finalized_slot = if (finalized_idx) |fin_idx| proto_nodes[fin_idx].slot else 0;

        // A block is orphaned if:
        // 1. It's at or before finalized slot, AND
        // 2. It's NOT on the canonical chain (not finalized)
        const is_orphaned = blk: {
            // Only blocks at or before finalized slot can be orphaned
            if (pnode.slot > finalized_slot) break :blk false;
            // If already finalized (canonical), not orphaned
            if (is_finalized) break :blk false;

            // If it's old enough to be finalized but isn't, it's orphaned
            break :blk true;
        };

        const role = if (is_finalized)
            "finalized"
        else if (is_justified)
            "justified"
        else if (is_head)
            "head"
        else if (is_orphaned)
            "orphaned"
        else
            "normal";

        // Normalized weight for arc (0.0 to 1.0, draws partial circle border)
        // Represents fraction of circle filled (0.5 = half circle, 1.0 = full circle)
        const arc_weight: f64 = if (max_weight > 0)
            @as(f64, @floatFromInt(pnode.weight)) / @as(f64, @floatFromInt(max_weight))
        else
            0.0;

        // Use separate arc fields for each color (only one is set per node, others are 0)
        // This allows manual arc section configuration with explicit colors
        // TODO: Use chain.forkChoice.isBlockTimely(blockDelayMs) once implemented
        // For now, treat all non-finalized/non-justified/non-head/non-orphaned blocks as timely
        const arc_timely: f64 = if (!is_finalized and !is_justified and !is_head and !is_orphaned) arc_weight else 0.0;
        const arc_head: f64 = if (is_head) arc_weight else 0.0;
        const arc_justified: f64 = if (is_justified) arc_weight else 0.0;
        const arc_finalized: f64 = if (is_finalized) arc_weight else 0.0;
        const arc_orphaned: f64 = if (is_orphaned) arc_weight else 0.0;

        // Block root as hex
        const hex_prefix = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(pnode.blockRoot[0..4])});
        defer allocator.free(hex_prefix);
        const full_root = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&pnode.blockRoot)});
        defer allocator.free(full_root);

        if (node_count > 0) {
            try nodes_list.appendSlice(",");
        }

        try std.fmt.format(nodes_list.writer(),
            \\{{"id":"{s}","title":"Slot {d}","mainStat":"{d}","secondaryStat":"{d}","arc__timely":{d:.4},"arc__head":{d:.4},"arc__justified":{d:.4},"arc__finalized":{d:.4},"arc__orphaned":{d:.4},"detail__role":"{s}","detail__hex_prefix":"{s}"}}
        , .{
            full_root,
            pnode.slot,
            pnode.weight,
            pnode.slot,
            arc_timely,
            arc_head,
            arc_justified,
            arc_finalized,
            arc_orphaned,
            role,
            hex_prefix,
        });

        node_count += 1;

        // Build edges (parent -> child relationships)
        if (pnode.parent) |parent_idx| {
            const parent_node = proto_nodes[parent_idx];
            if (parent_node.slot >= min_slot) {
                const parent_root = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&parent_node.blockRoot)});
                defer allocator.free(parent_root);

                const is_best_child = if (parent_node.bestChild) |bc| bc == idx else false;

                if (edge_count > 0) {
                    try edges_list.appendSlice(",");
                }

                try std.fmt.format(edges_list.writer(),
                    \\{{"id":"edge_{d}","source":"{s}","target":"{s}","mainStat":"","detail__is_best_child":{}}}
                , .{
                    edge_count,
                    parent_root,
                    full_root,
                    is_best_child,
                });

                edge_count += 1;
            }
        }
    }

    // Write final JSON
    try std.fmt.format(writer,
        \\{{"nodes":[{s}],"edges":[{s}]}}
    , .{ nodes_list.items, edges_list.items });
}
