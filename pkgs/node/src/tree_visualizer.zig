const std = @import("std");
const Allocator = std.mem.Allocator;
const fcFactory = @import("./forkchoice.zig");
const constants = @import("./constants.zig");

/// Builds a tree visualization of the fork choice tree with optional depth limit
pub fn buildTreeVisualization(allocator: Allocator, nodes: []const fcFactory.ProtoNode, max_depth: ?usize, max_branch: ?usize) ![]const u8 {
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
        try visualizeTreeBranch(allocator, &tree_lines, nodes, root_idx, 0, 0, "", max_depth, max_branch);
    }

    return tree_lines.toOwnedSlice(allocator);
}

const RecentChildren = struct { id: usize, recency: usize };
fn sortDescByRecency(context: void, a: RecentChildren, b: RecentChildren) bool {
    _ = context;
    return a.recency > b.recency;
}

/// Recursively builds a tree branch visualization
fn visualizeTreeBranch(allocator: Allocator, tree_lines: *std.ArrayListUnmanaged(u8), nodes: []const fcFactory.ProtoNode, node_idx: usize, depth: usize, branch: usize, prefix: []const u8, maxDepth: ?usize, maxBranch: ?usize) !void {
    const node = nodes[node_idx];
    const hex_root = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(node.blockRoot[0..2])});
    defer allocator.free(hex_root);

    const max_depth = maxDepth orelse constants.MAX_FC_DISPLAY_DEPTH;
    const max_branch = maxBranch orelse constants.MAX_FC_DISPLAY_BRANCH;

    const lead_node_idx = node.bestDescendant orelse node_idx;
    const leaf_node = nodes[lead_node_idx];
    const leaf_distance = leaf_node.depth - node.depth;

    // get children and order them
    var children = std.ArrayList(RecentChildren).init(allocator);
    defer children.deinit();

    var c_idx = node.firstChild;
    while (c_idx > 0) {
        const child_node = nodes[c_idx];
        try children.append(.{ .id = c_idx, .recency = child_node.bestDescendant orelse child_node.slot });

        c_idx = child_node.nextSibling;
    }

    // always display root, or when not far from the leaf or this is a fork point
    var is_node_printed: bool = false;
    const parentOrNull = if (node.parent) |parent_idx| nodes[parent_idx] else null;
    if (depth < 1 or leaf_distance <= max_depth - 1 or children.items.len > 1 or
        //
        (if (parentOrNull) |parent| (parent.firstChild != parent.latestChild) else true)
        //
    ) {
        // code retained for print debugging
        // const node_line = try std.fmt.allocPrint(allocator, "{s}{s}({d} d-{d} nS-{d} fC={d} lC={d} nB={any} ld={d})", .{ prefix, hex_root, node.slot, node.depth, node.nextSibling, node.firstChild, node.latestChild, node.numBranches, leaf_distance });

        const node_line = try std.fmt.allocPrint(allocator, "{s}{s}({d})", .{ prefix, hex_root, node.slot });
        defer allocator.free(node_line);

        try tree_lines.appendSlice(allocator, node_line);
        is_node_printed = true;
    }

    // we sort and go multi line only if more than 1 child
    if (children.items.len > 1) {
        std.mem.sort(RecentChildren, children.items, {}, sortDescByRecency);

        const child_count_comment = try std.fmt.allocPrint(allocator, " - {d} branches", .{node.numChildren});
        defer allocator.free(child_count_comment);
        try tree_lines.appendSlice(allocator, child_count_comment);
        try tree_lines.append(allocator, '\n');
    } else {
        // single branch check if child will be truncated, equivalent to leaf_distance -1 > max_depth -1
        if (is_node_printed and leaf_distance > max_depth) {
            const truncation_comment = try std.fmt.allocPrint(allocator, "... ", .{});
            defer allocator.free(truncation_comment);
            try tree_lines.appendSlice(allocator, truncation_comment);
        }
    }

    for (children.items, 0..) |recent_child, child_i| {
        // Check if we've reached the maximum fanout
        if (branch + child_i >= max_branch) {
            const truncated_comment = try std.fmt.allocPrint(allocator, " ... (truncated at branch {d})", .{max_branch});
            defer allocator.free(truncated_comment);
            try tree_lines.appendSlice(allocator, truncated_comment);
            try tree_lines.append(allocator, '\n');
            return;
        }

        const child_idx = recent_child.id;

        // print child separators only if this node was printed
        if (is_node_printed) {
            const child_node = nodes[child_idx];
            const is_last_child = child_i == children.items.len - 1;

            const indent = if (children.items.len > 1) try createTreeIndent(allocator, depth, is_last_child) else "─ ";
            defer if (children.items.len > 1) allocator.free(indent);

            // Check for missing slots between parent and child
            if (child_node.slot > node.slot + 1) {
                const missing_slots = child_node.slot - node.slot - 1;
                const missing_line = if (missing_slots == 1)
                    try std.fmt.allocPrint(allocator, "{s}[ ]─ ", .{indent})
                else
                    try std.fmt.allocPrint(allocator, "{s}[{d}]─ ", .{ indent, missing_slots });
                defer allocator.free(missing_line);
                try tree_lines.appendSlice(allocator, missing_line);
            } else {
                try tree_lines.appendSlice(allocator, indent);
            }
        }

        // Recursively process child
        try visualizeTreeBranch(allocator, tree_lines, nodes, child_idx, depth + 1, branch + child_i, "", max_depth, max_branch);

        // In multi-branch mode, separate sibling branches with newlines
        // Only add newline if the last character isn't already a newline (avoid double newlines from sub-forks)
        if (children.items.len > 1) {
            if (tree_lines.items.len == 0 or tree_lines.items[tree_lines.items.len - 1] != '\n') {
                try tree_lines.append(allocator, '\n');
            }
        }
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

// ============================================================================
// TESTS FOR buildTreeVisualization
// ============================================================================

const types = @import("@zeam/types");
const Root = types.Root;

/// Helper function to create a deterministic test root filled with a specific byte
fn createTestRoot(fill_byte: u8) Root {
    var root: Root = undefined;
    @memset(&root, fill_byte);
    return root;
}

/// Helper function to create a ProtoNode for testing
fn createTestProtoNode(
    slot: types.Slot,
    block_root_byte: u8,
    parent_root_byte: u8,
    parent: ?usize,
    depth: usize,
    first_child: usize,
    latest_child: usize,
    next_sibling: usize,
    num_children: usize,
    best_descendant: ?usize,
) fcFactory.ProtoNode {
    return fcFactory.ProtoNode{
        .slot = slot,
        .blockRoot = createTestRoot(block_root_byte),
        .parentRoot = createTestRoot(parent_root_byte),
        .stateRoot = createTestRoot(0x00),
        .timeliness = true,
        .confirmed = true,
        .parent = parent,
        .weight = 0,
        .bestChild = null,
        .bestDescendant = best_descendant,
        .depth = depth,
        .nextSibling = next_sibling,
        .firstChild = first_child,
        .latestChild = latest_child,
        .numChildren = num_children,
        .numBranches = null,
    };
}

test "buildTreeVisualization: empty nodes array" {
    const allocator = std.testing.allocator;
    const nodes: []const fcFactory.ProtoNode = &.{};

    const result = try buildTreeVisualization(allocator, nodes, null, null);
    defer allocator.free(result);

    // Empty array should produce empty output
    try std.testing.expectEqualStrings("", result);

    std.debug.print("\n=== TEST: empty nodes array ===\n", .{});
    std.debug.print("Output: '{s}'\n", .{result});
}

test "buildTreeVisualization: single root node with no children" {
    const allocator = std.testing.allocator;

    // Single node: slot 0, root 0xAA, no parent, no children
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 0, 0, 0, 0, null),
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, null);
    defer allocator.free(result);

    // Should output "aaaa(0)" - first 2 bytes of blockRoot in hex + (slot)
    try std.testing.expectEqualStrings("aaaa(0)", result);

    std.debug.print("\n=== TEST: single root node ===\n", .{});
    std.debug.print("Output: '{s}'\n", .{result});
}

test "buildTreeVisualization: linear chain (no forks)" {
    const allocator = std.testing.allocator;

    // Linear chain: A(0) -> B(1) -> C(2)
    // Node 0: slot 0, root 0xAA, parent null, firstChild=1
    // Node 1: slot 1, root 0xBB, parent 0, firstChild=2
    // Node 2: slot 2, root 0xCC, parent 1, no children
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 1, 0, 1, 2), // A: root, child is B, bestDescendant is C
        createTestProtoNode(1, 0xBB, 0xAA, 0, 1, 2, 2, 0, 1, 2), // B: parent A, child is C
        createTestProtoNode(2, 0xCC, 0xBB, 1, 2, 0, 0, 0, 0, null), // C: parent B, no children
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, null);
    defer allocator.free(result);

    // Linear chain should show: aaaa(0)─ bbbb(1)─ cccc(2)
    try std.testing.expectEqualStrings("aaaa(0)─ bbbb(1)─ cccc(2)", result);

    std.debug.print("\n=== TEST: linear chain ===\n", .{});
    std.debug.print("Output: '{s}'\n", .{result});
}

test "buildTreeVisualization: simple fork with two branches" {
    const allocator = std.testing.allocator;

    // Fork: A(0) has two children B(1) and C(1)
    //       A(0)
    //      /    \
    //   B(1)    C(1)
    //
    // Node 0: slot 0, root 0xAA, firstChild=1, latestChild=2, numChildren=2
    // Node 1: slot 1, root 0xBB, parent 0, nextSibling=2
    // Node 2: slot 1, root 0xCC, parent 0, nextSibling=0
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 2, 0, 2, null), // A: root with 2 children
        createTestProtoNode(1, 0xBB, 0xAA, 0, 1, 0, 0, 2, 0, null), // B: child of A, sibling C
        createTestProtoNode(1, 0xCC, 0xAA, 0, 1, 0, 0, 0, 0, null), // C: child of A, no sibling
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, null);
    defer allocator.free(result);

    // Should show fork structure with branches
    // Expected format when multiple children: "aaaa(0) - 2 branches\n├── bbbb(1)\n└── cccc(1)"
    // Note: children are sorted by recency (bestDescendant or slot), both have slot=1 so order may vary
    std.debug.print("\n=== TEST: simple fork ===\n", .{});
    std.debug.print("Output:\n{s}\n", .{result});

    // Verify it contains the expected elements
    try std.testing.expect(std.mem.indexOf(u8, result, "aaaa(0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "- 2 branches") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "bbbb(1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "cccc(1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "├──") != null or std.mem.indexOf(u8, result, "└──") != null);
}

test "buildTreeVisualization: missing slots indicator (single slot)" {
    const allocator = std.testing.allocator;

    // Chain with missing slot: A(0) -> B(2) (slot 1 is missing)
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 1, 0, 1, 1), // A: slot 0
        createTestProtoNode(2, 0xBB, 0xAA, 0, 1, 0, 0, 0, 0, null), // B: slot 2 (missing slot 1)
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, null);
    defer allocator.free(result);

    // Should show "[ ]" for single missing slot
    std.debug.print("\n=== TEST: missing slot (single) ===\n", .{});
    std.debug.print("Output: '{s}'\n", .{result});

    try std.testing.expect(std.mem.indexOf(u8, result, "[ ]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "aaaa(0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "bbbb(2)") != null);
}

test "buildTreeVisualization: missing slots indicator (multiple slots)" {
    const allocator = std.testing.allocator;

    // Chain with multiple missing slots: A(0) -> B(4) (slots 1,2,3 are missing)
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 1, 0, 1, 1), // A: slot 0
        createTestProtoNode(4, 0xBB, 0xAA, 0, 1, 0, 0, 0, 0, null), // B: slot 4 (missing slots 1,2,3)
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, null);
    defer allocator.free(result);

    // Should show "[3]" for 3 missing slots
    std.debug.print("\n=== TEST: missing slots (multiple) ===\n", .{});
    std.debug.print("Output: '{s}'\n", .{result});

    try std.testing.expect(std.mem.indexOf(u8, result, "[3]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "aaaa(0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "bbbb(4)") != null);
}

test "buildTreeVisualization: max depth truncation" {
    const allocator = std.testing.allocator;

    // Deep chain: A(0) -> B(1) -> C(2) -> D(3) -> E(4)
    // With max_depth=2, should truncate middle nodes and show root + near-leaf nodes
    // Print logic: root (depth<1) always printed. B,C skipped (leaf_distance > max_depth-1
    // and single child, not fork). D printed (leaf_distance=1 <= max_depth-1=1). E printed (leaf_distance=0).
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 1, 0, 1, 4), // A
        createTestProtoNode(1, 0xBB, 0xAA, 0, 1, 2, 2, 0, 1, 4), // B
        createTestProtoNode(2, 0xCC, 0xBB, 1, 2, 3, 3, 0, 1, 4), // C
        createTestProtoNode(3, 0xDD, 0xCC, 2, 3, 4, 4, 0, 1, 4), // D
        createTestProtoNode(4, 0xEE, 0xDD, 3, 4, 0, 0, 0, 0, null), // E: leaf
    };

    const result = try buildTreeVisualization(allocator, &nodes, 2, null);
    defer allocator.free(result);

    std.debug.print("\n=== TEST: max depth truncation ===\n", .{});
    std.debug.print("Output: '{s}'\n", .{result});

    // Root should always be shown
    try std.testing.expect(std.mem.indexOf(u8, result, "aaaa(0)") != null);
    // Should contain truncation indicator "... " (appended when leaf_distance > max_depth on a single-child node)
    try std.testing.expect(std.mem.indexOf(u8, result, "... ") != null);
    // Near-leaf nodes D and E should be rendered (within max_depth of leaf)
    try std.testing.expect(std.mem.indexOf(u8, result, "dddd(3)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "eeee(4)") != null);
    // Middle nodes B and C should be skipped (too far from leaf, not a fork point)
    try std.testing.expect(std.mem.indexOf(u8, result, "bbbb(1)") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "cccc(2)") == null);
}

test "buildTreeVisualization: max branch truncation" {
    const allocator = std.testing.allocator;

    // Wide fork: A(0) has 4 children B, C, D, E
    // With max_branch=2, should truncate after 2 branches
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 4, 0, 4, null), // A: root with 4 children
        createTestProtoNode(1, 0xBB, 0xAA, 0, 1, 0, 0, 2, 0, null), // B
        createTestProtoNode(1, 0xCC, 0xAA, 0, 1, 0, 0, 3, 0, null), // C
        createTestProtoNode(1, 0xDD, 0xAA, 0, 1, 0, 0, 4, 0, null), // D
        createTestProtoNode(1, 0xEE, 0xAA, 0, 1, 0, 0, 0, 0, null), // E
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, 2);
    defer allocator.free(result);

    std.debug.print("\n=== TEST: max branch truncation ===\n", .{});
    std.debug.print("Output:\n{s}\n", .{result});

    // Should contain branch truncation indicator
    try std.testing.expect(std.mem.indexOf(u8, result, "aaaa(0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "truncated at branch 2") != null);
}

test "buildTreeVisualization: complex tree with forks at multiple levels" {
    const allocator = std.testing.allocator;

    // Complex tree:
    //         A(0)
    //        /    \
    //      B(1)   C(1)
    //      /
    //    D(2)
    //
    // Node indices: A=0, B=1, C=2, D=3
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 2, 0, 2, 3), // A: root, children B,C
        createTestProtoNode(1, 0xBB, 0xAA, 0, 1, 3, 3, 2, 1, 3), // B: child of A, has child D
        createTestProtoNode(1, 0xCC, 0xAA, 0, 1, 0, 0, 0, 0, null), // C: child of A, no children
        createTestProtoNode(2, 0xDD, 0xBB, 1, 2, 0, 0, 0, 0, null), // D: child of B
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, null);
    defer allocator.free(result);

    std.debug.print("\n=== TEST: complex tree with multi-level forks ===\n", .{});
    std.debug.print("Output:\n{s}\n", .{result});

    // Verify all nodes are present
    try std.testing.expect(std.mem.indexOf(u8, result, "aaaa(0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "bbbb(1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "cccc(1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "dddd(2)") != null);
    // Should indicate A has 2 branches
    try std.testing.expect(std.mem.indexOf(u8, result, "- 2 branches") != null);
}

test "buildTreeVisualization: multiple root nodes (disconnected trees)" {
    const allocator = std.testing.allocator;

    // Two disconnected trees:
    // Tree 1: A(0) -> B(1)
    // Tree 2: C(0) -> D(1)
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 1, 0, 1, 1), // A: root of tree 1
        createTestProtoNode(1, 0xBB, 0xAA, 0, 1, 0, 0, 0, 0, null), // B: child of A
        createTestProtoNode(0, 0xCC, 0x00, null, 0, 3, 3, 0, 1, 3), // C: root of tree 2
        createTestProtoNode(1, 0xDD, 0xCC, 2, 1, 0, 0, 0, 0, null), // D: child of C
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, null);
    defer allocator.free(result);

    std.debug.print("\n=== TEST: multiple root nodes ===\n", .{});
    std.debug.print("Output: '{s}'\n", .{result});

    // Both trees should be visualized
    try std.testing.expect(std.mem.indexOf(u8, result, "aaaa(0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "bbbb(1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "cccc(0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "dddd(1)") != null);
}

test "buildTreeVisualization: children sorted by recency (highest bestDescendant first)" {
    const allocator = std.testing.allocator;

    // Fork: A(0) has two children B(1) and C(1)
    // B has bestDescendant=5 (recency=5), C has bestDescendant=4 (recency=4)
    // B should appear before C in output since higher recency is sorted first
    //
    //       A(0)
    //      /    \
    //   B(1)    C(1)
    //    |        |
    //   D(2)    E(2)
    //    |
    //   F(3)
    //
    // Node indices: A=0, B=1, C=2, D=3, E=4, F=5
    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 2, 0, 2, 5), // A: root, 2 children
        createTestProtoNode(1, 0xBB, 0xAA, 0, 1, 3, 3, 2, 1, 5), // B: child of A, bestDescendant=5 (recency=5)
        createTestProtoNode(1, 0xCC, 0xAA, 0, 1, 4, 4, 0, 1, 4), // C: child of A, bestDescendant=4 (recency=4)
        createTestProtoNode(2, 0xDD, 0xBB, 1, 2, 5, 5, 0, 1, 5), // D: child of B
        createTestProtoNode(2, 0xEE, 0xCC, 2, 2, 0, 0, 0, 0, null), // E: child of C (leaf)
        createTestProtoNode(3, 0xFF, 0xDD, 3, 3, 0, 0, 0, 0, null), // F: child of D (leaf)
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, null);
    defer allocator.free(result);

    std.debug.print("\n=== TEST: children sorted by recency ===\n", .{});
    std.debug.print("Output:\n{s}\n", .{result});

    // Both branches should be present
    try std.testing.expect(std.mem.indexOf(u8, result, "aaaa(0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "bbbb(1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "cccc(1)") != null);

    // B (recency=5) should appear before C (recency=4) in the output
    const b_pos = std.mem.indexOf(u8, result, "bbbb(1)").?;
    const c_pos = std.mem.indexOf(u8, result, "cccc(1)").?;
    try std.testing.expect(b_pos < c_pos);
}

test "buildTreeVisualization: fork choice tree with fork (printSlot style)" {
    // This test creates a realistic fork-choice scenario similar to printSlot:
    // Genesis(0) -> Block1(1) which forks into Block2a(2) and Block2b(2)
    // This goes beyond a simple linear chain to validate fork rendering.
    const allocator = std.testing.allocator;

    var nodes = [_]fcFactory.ProtoNode{
        createTestProtoNode(0, 0x00, 0x00, null, 0, 1, 1, 0, 1, 2), // Genesis at slot 0
        createTestProtoNode(1, 0x11, 0x00, 0, 1, 2, 3, 0, 2, 2), // Block1 forks into 2 children
        createTestProtoNode(2, 0x22, 0x11, 1, 2, 0, 0, 3, 0, null), // Block2a
        createTestProtoNode(2, 0x33, 0x11, 1, 2, 0, 0, 0, 0, null), // Block2b
    };

    const result = try buildTreeVisualization(allocator, &nodes, null, null);
    defer allocator.free(result);

    std.debug.print("\n=== TEST: fork choice tree with fork (printSlot style) ===\n", .{});
    std.debug.print("ForkChoice Tree:\n{s}\n", .{result});

    // Verify the chain structure
    try std.testing.expect(std.mem.indexOf(u8, result, "0000(0)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "1111(1)") != null);
    // Both fork branches should be present
    try std.testing.expect(std.mem.indexOf(u8, result, "2222(2)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "3333(2)") != null);
    // Block1 has 2 children so should indicate branches
    try std.testing.expect(std.mem.indexOf(u8, result, "- 2 branches") != null);
    // Should use tree branch characters
    try std.testing.expect(std.mem.indexOf(u8, result, "├──") != null or std.mem.indexOf(u8, result, "└──") != null);
}

test "buildTreeVisualization: big tree with many branches and depth (max_depth=10, max_branches=10)" {
    // Big tree test to visualize BOTH branch and depth truncation with realistic limits
    // Structure:
    //   Root(0) - 12 branches (exceeds max_branches=10, triggers branch truncation)
    //     ├── Branch1: 12 blocks deep (slots 1->12, exceeds max_depth=10, triggers depth truncation)
    //     ├── Branch2: 6 blocks deep with sub-fork at slot 3
    //     ├── Branch3-12: leaf nodes (slots 1)
    //
    // This tests:
    // 1. Branch truncation (12 > 10) - "truncated at branch 10"
    // 2. Depth truncation (12 > 10) - "... " marker in Branch1
    // 3. Sub-forks within branches - "- 2 branches" for D2's fork
    // 4. Visual output showing both limits working together
    const allocator = std.testing.allocator;

    // Node indices:
    // 0: Root
    // 1-12: 12 children of root (Branch1-12)
    // 13-23: Chain for Branch1 (11 more nodes, slots 2-12) - total depth 12
    // 24-28: Chain for Branch2 with fork (slots 2-5, with fork at 25)
    var nodes = [_]fcFactory.ProtoNode{
        // Root: slot 0, 12 children (indices 1-12)
        createTestProtoNode(0, 0xAA, 0x00, null, 0, 1, 12, 0, 12, 23), // bestDescendant=23 (end of Branch1)

        // Branch1: deep chain of 12 blocks (indices 1, 13-23)
        createTestProtoNode(1, 0xB1, 0xAA, 0, 1, 13, 13, 2, 1, 23), // B1 slot 1, depth 1
        // Branch2: chain with fork (indices 2, 24-28)
        createTestProtoNode(1, 0xB2, 0xAA, 0, 1, 24, 24, 3, 1, 28), // B2 slot 1
        // Branches 3-12: leaf nodes
        createTestProtoNode(1, 0xB3, 0xAA, 0, 1, 0, 0, 4, 0, null), // B3
        createTestProtoNode(1, 0xB4, 0xAA, 0, 1, 0, 0, 5, 0, null), // B4
        createTestProtoNode(1, 0xB5, 0xAA, 0, 1, 0, 0, 6, 0, null), // B5
        createTestProtoNode(1, 0xB6, 0xAA, 0, 1, 0, 0, 7, 0, null), // B6
        createTestProtoNode(1, 0xB7, 0xAA, 0, 1, 0, 0, 8, 0, null), // B7
        createTestProtoNode(1, 0xB8, 0xAA, 0, 1, 0, 0, 9, 0, null), // B8
        createTestProtoNode(1, 0xB9, 0xAA, 0, 1, 0, 0, 10, 0, null), // B9
        createTestProtoNode(1, 0xBA, 0xAA, 0, 1, 0, 0, 11, 0, null), // B10
        createTestProtoNode(1, 0xBB, 0xAA, 0, 1, 0, 0, 12, 0, null), // B11
        createTestProtoNode(1, 0xBC, 0xAA, 0, 1, 0, 0, 0, 0, null), // B12 (last, no sibling)

        // Branch1 chain continuation (indices 13-23, slots 2-12) - 12 total depth
        createTestProtoNode(2, 0xC1, 0xB1, 1, 2, 14, 14, 0, 1, 23), // slot 2, depth 2
        createTestProtoNode(3, 0xD1, 0xC1, 13, 3, 15, 15, 0, 1, 23), // slot 3, depth 3
        createTestProtoNode(4, 0xE1, 0xD1, 14, 4, 16, 16, 0, 1, 23), // slot 4, depth 4
        createTestProtoNode(5, 0xF1, 0xE1, 15, 5, 17, 17, 0, 1, 23), // slot 5, depth 5
        createTestProtoNode(6, 0x11, 0xF1, 16, 6, 18, 18, 0, 1, 23), // slot 6, depth 6
        createTestProtoNode(7, 0x12, 0x11, 17, 7, 19, 19, 0, 1, 23), // slot 7, depth 7
        createTestProtoNode(8, 0x13, 0x12, 18, 8, 20, 20, 0, 1, 23), // slot 8, depth 8
        createTestProtoNode(9, 0x14, 0x13, 19, 9, 21, 21, 0, 1, 23), // slot 9, depth 9
        createTestProtoNode(10, 0x15, 0x14, 20, 10, 22, 22, 0, 1, 23), // slot 10, depth 10
        createTestProtoNode(11, 0x16, 0x15, 21, 11, 23, 23, 0, 1, 23), // slot 11, depth 11
        createTestProtoNode(12, 0x17, 0x16, 22, 12, 0, 0, 0, 0, null), // slot 12, depth 12 (leaf)

        // Branch2 chain with fork (indices 24-28)
        createTestProtoNode(2, 0xC2, 0xB2, 2, 2, 25, 25, 0, 1, 28), // C2 slot 2
        createTestProtoNode(3, 0xD2, 0xC2, 24, 3, 26, 27, 0, 2, 28), // D2 slot 3 - FORK: 2 children
        createTestProtoNode(4, 0xE2, 0xD2, 25, 4, 28, 28, 27, 1, 28), // E2a slot 4 (fork branch a)
        createTestProtoNode(4, 0xE3, 0xD2, 25, 4, 0, 0, 0, 0, null), // E2b slot 4 (fork branch b, leaf)
        createTestProtoNode(5, 0xF2, 0xE2, 26, 5, 0, 0, 0, 0, null), // F2 slot 5 (leaf of branch a)
    };

    const result = try buildTreeVisualization(allocator, &nodes, 10, 10);
    defer allocator.free(result);

    std.debug.print("\n=== TEST: big tree with many branches (max_depth=10, max_branches=10) ===\n", .{});
    std.debug.print("ForkChoice Tree:\n{s}\n", .{result});

    // Verify root is present
    try std.testing.expect(std.mem.indexOf(u8, result, "aaaa(0)") != null);

    // Verify it shows 12 branches
    try std.testing.expect(std.mem.indexOf(u8, result, "- 12 branches") != null);

    // Verify branch truncation occurs (should see "truncated at branch 10")
    try std.testing.expect(std.mem.indexOf(u8, result, "truncated at branch 10") != null);

    // Verify depth truncation occurs in Branch1 (should see "... " marker)
    try std.testing.expect(std.mem.indexOf(u8, result, "... ") != null);

    // Verify Branch1's start is visible
    try std.testing.expect(std.mem.indexOf(u8, result, "b1b1(1)") != null);

    // Verify Branch1's leaf (slot 12) is visible (near-leaf nodes shown despite depth truncation)
    try std.testing.expect(std.mem.indexOf(u8, result, "1717(12)") != null);

    // Verify Branch2's sub-fork is present and shows as a fork
    try std.testing.expect(std.mem.indexOf(u8, result, "d2d2(3)") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "- 2 branches") != null); // D2's fork indicator

    // Verify tree structure characters are used
    try std.testing.expect(std.mem.indexOf(u8, result, "├──") != null);
}
