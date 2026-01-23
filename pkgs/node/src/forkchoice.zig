const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;

const ssz = @import("ssz");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const zeam_utils = @import("@zeam/utils");
const stf = @import("@zeam/state-transition");
const zeam_metrics = @import("@zeam/metrics");
const params = @import("@zeam/params");

const constants = @import("./constants.zig");

const AggregatedSignatureProof = types.AggregatedSignatureProof;
const Root = types.Root;
const ValidatorIndex = types.ValidatorIndex;
const ZERO_SIGBYTES = types.ZERO_SIGBYTES;

const ProtoBlock = types.ProtoBlock;
const ProtoMeta = struct {
    parent: ?usize,
    weight: isize,
    bestChild: ?usize,
    bestDescendant: ?usize,
};
pub const ProtoNode = zeam_utils.MixIn(ProtoBlock, ProtoMeta);

pub const ProtoArray = struct {
    nodes: std.ArrayList(ProtoNode),
    indices: std.AutoHashMap(types.Root, usize),

    const Self = @This();
    pub fn init(allocator: Allocator, anchorBlock: ProtoBlock) !Self {
        const nodes = std.ArrayList(ProtoNode).init(allocator);
        const indices = std.AutoHashMap(types.Root, usize).init(allocator);

        var proto_array = Self{
            .nodes = nodes,
            .indices = indices,
        };
        try proto_array.onBlock(anchorBlock, anchorBlock.slot);
        return proto_array;
    }

    pub fn onBlock(self: *Self, block: ProtoBlock, currentSlot: types.Slot) !void {
        const onblock_timer = zeam_metrics.lean_fork_choice_block_processing_time_seconds.start();
        defer _ = onblock_timer.observe();

        // currentSlot might be needed in future for finding the viable head
        _ = currentSlot;
        const node_or_null = self.indices.get(block.blockRoot);
        if (node_or_null) |node| {
            _ = node;
            return;
        }

        const parent = self.indices.get(block.parentRoot);

        // TODO extend is not working so copy data for now
        // const node = utils.Extend(ProtoNode, block, .{
        //     .parent = parent,
        //     .weight = weight,
        //     // bestChild and bestDescendant are left null
        // });
        const node = ProtoNode{
            .slot = block.slot,
            .blockRoot = block.blockRoot,
            .parentRoot = block.parentRoot,
            .stateRoot = block.stateRoot,
            .timeliness = block.timeliness,
            .confirmed = block.confirmed,
            .parent = parent,
            .weight = 0,
            .bestChild = null,
            .bestDescendant = null,
        };
        const node_index = self.nodes.items.len;
        try self.nodes.append(node);
        try self.indices.put(node.blockRoot, node_index);
    }

    fn getNode(self: *Self, blockRoot: types.Root) ?ProtoNode {
        const block_index = self.indices.get(blockRoot);
        if (block_index) |blkidx| {
            const node = self.nodes.items[blkidx];
            return node;
        } else {
            return null;
        }
    }

    pub fn applyDeltas(self: *Self, deltas: []isize, cutoff_weight: u64) !void {
        if (deltas.len != self.nodes.items.len) {
            return ForkChoiceError.InvalidDeltas;
        }

        // iterate backwards apply deltas and propagating deltas to parents
        for (0..self.nodes.items.len) |i| {
            const node_idx = self.nodes.items.len - 1 - i;
            const node_delta = deltas[node_idx];
            self.nodes.items[node_idx].weight += node_delta;
            if (self.nodes.items[node_idx].parent) |parent_idx| {
                deltas[parent_idx] += node_delta;
            }
        }

        // re-iterate backwards and calc best child and descendant
        // there seems to be no filter block tree in the mini3sf fc
        for (0..self.nodes.items.len) |i| {
            const node_idx = self.nodes.items.len - 1 - i;
            const node = self.nodes.items[node_idx];

            if (self.nodes.items[node_idx].parent) |parent_idx| {
                const nodeBestDescendant = node.bestDescendant orelse (
                    // by recurssion, we will always have a bestDescendant >= cutoff
                    if (self.nodes.items[node_idx].weight >= cutoff_weight) node_idx else null
                    //
                );

                const parent = self.nodes.items[parent_idx];
                var updateBest = false;

                if (parent.bestChild == node_idx) {
                    // check if bestDescendant needs to be updated even if best child is same
                    if (parent.bestDescendant != nodeBestDescendant) {
                        updateBest = true;
                    }
                } else {
                    const bestChildOrNull = if (parent.bestChild) |bestChildIdx| self.nodes.items[bestChildIdx] else null;

                    // see if we can update parent's best
                    if (bestChildOrNull) |bestChild| {
                        if (bestChild.weight < node.weight) {
                            updateBest = true;
                        } else if (bestChild.weight == node.weight) {
                            // tie break by slot else by hash
                            if (node.slot > bestChild.slot) {
                                updateBest = true;
                            } else if (node.slot == bestChild.slot and (std.mem.order(u8, &bestChild.blockRoot, &node.blockRoot) == .lt)) {
                                updateBest = true;
                            }
                        }
                    } else {
                        updateBest = true;
                    }
                }

                if (updateBest) {
                    self.nodes.items[parent_idx].bestChild = node_idx;
                    self.nodes.items[parent_idx].bestDescendant = nodeBestDescendant;
                }
            }
        }
    }
};

const OnBlockOpts = struct {
    currentSlot: types.Slot,
    blockDelayMs: u64,
    blockRoot: ?types.Root = null,
    confirmed: bool,
};

pub const ForkChoiceStore = struct {
    // time in intervals and slots since genesis
    time: types.Interval,
    timeSlots: types.Slot,

    latest_justified: types.Checkpoint,
    // finalized is not tracked the same way in 3sf mini as it corresponds to head's finalized
    // however its unlikely that a finalized can be rolled back in a normal node operation
    // (for example a buggy chain has been finalized in which case node should be started with
    //  anchor of the new non buggy branch)
    latest_finalized: types.Checkpoint,

    const Self = @This();
    pub fn update(self: *Self, justified: types.Checkpoint, finalized: types.Checkpoint) void {
        if (justified.slot > self.latest_justified.slot) {
            self.latest_justified = justified;
        }

        if (finalized.slot > self.latest_finalized.slot) {
            self.latest_finalized = finalized;
        }
    }
};

const ProtoAttestation = struct {
    //
    index: usize = 0,
    slot: types.Slot = 0,
    // we store AttestationData here since signatures are stored separately in gossip_signatures/aggregated_payloads
    attestation_data: ?types.AttestationData = null,
};

const AttestationTracker = struct {
    // prev latest attestation applied index null if not applied
    appliedIndex: ?usize = null,
    // latest known on-chain attestation of the validator
    latestKnown: ?ProtoAttestation = null,
    // nlatest new attestation of validator not yet seen on-chain
    latestNew: ?ProtoAttestation = null,
};

pub const ForkChoiceParams = struct {
    config: configs.ChainConfig,
    anchorState: *const types.BeamState,
    logger: zeam_utils.ModuleLogger,
};

// Use shared signature map types from types package
const SignatureKey = types.SignatureKey;
const StoredSignature = types.StoredSignature;
const SignaturesMap = types.SignaturesMap;
const StoredAggregatedPayload = types.StoredAggregatedPayload;
const AggregatedPayloadsList = types.AggregatedPayloadsList;
const AggregatedPayloadsMap = types.AggregatedPayloadsMap;

pub const ForkChoice = struct {
    protoArray: ProtoArray,
    anchorState: *const types.BeamState,
    config: configs.ChainConfig,
    fcStore: ForkChoiceStore,
    allocator: Allocator,
    // map of validator ids to attestation tracker, better to have a map instead of array
    // because of churn in validators
    attestations: std.AutoHashMap(usize, AttestationTracker),
    head: ProtoBlock,
    safeTarget: ProtoBlock,
    // data structure to hold validator deltas, could be grown over time as more validators
    // get added
    deltas: std.ArrayList(isize),
    logger: zeam_utils.ModuleLogger,
    // Per-validator XMSS signatures learned from gossip, keyed by (validator_id, attestation_data_root)
    gossip_signatures: SignaturesMap,
    // Aggregated signature proofs learned from blocks, keyed by (validator_id, attestation_data_root)
    // Values are lists since we may receive multiple proofs for the same key from different blocks
    aggregated_payloads: AggregatedPayloadsMap,

    const Self = @This();
    pub fn init(allocator: Allocator, opts: ForkChoiceParams) !Self {
        const anchor_block_header = try opts.anchorState.genStateBlockHeader(allocator);
        var anchor_block_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            types.BeamBlockHeader,
            anchor_block_header,
            &anchor_block_root,
            allocator,
        );

        const anchor_block = ProtoBlock{
            .slot = opts.anchorState.slot,
            .blockRoot = anchor_block_root,
            .parentRoot = anchor_block_header.parent_root,
            .stateRoot = anchor_block_header.state_root,
            .timeliness = true,
            .confirmed = true,
        };
        const proto_array = try ProtoArray.init(allocator, anchor_block);
        const anchorCP = types.Checkpoint{ .slot = opts.anchorState.slot, .root = anchor_block_root };
        const fc_store = ForkChoiceStore{
            .time = opts.anchorState.slot * constants.INTERVALS_PER_SLOT,
            .timeSlots = opts.anchorState.slot,
            .latest_justified = anchorCP,
            .latest_finalized = anchorCP,
        };
        const attestations = std.AutoHashMap(usize, AttestationTracker).init(allocator);
        const deltas = std.ArrayList(isize).init(allocator);
        const gossip_signatures = SignaturesMap.init(allocator);
        const aggregated_payloads = AggregatedPayloadsMap.init(allocator);

        var fc = Self{
            .allocator = allocator,
            .protoArray = proto_array,
            .anchorState = opts.anchorState,
            .config = opts.config,
            .fcStore = fc_store,
            .attestations = attestations,
            .head = anchor_block,
            .safeTarget = anchor_block,
            .deltas = deltas,
            .logger = opts.logger,
            .gossip_signatures = gossip_signatures,
            .aggregated_payloads = aggregated_payloads,
        };
        _ = try fc.updateHead();
        return fc;
    }

    pub fn deinit(self: *Self) void {
        self.protoArray.nodes.deinit();
        self.protoArray.indices.deinit();
        self.attestations.deinit();
        self.deltas.deinit();
        self.gossip_signatures.deinit();

        // Deinit each list in the aggregated_payloads map
        var it = self.aggregated_payloads.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |*stored| {
                stored.proof.deinit();
            }
            entry.value_ptr.deinit();
        }
        self.aggregated_payloads.deinit();
    }

    fn isBlockTimely(self: *Self, blockDelayMs: usize) bool {
        _ = self;
        _ = blockDelayMs;
        return true;
    }

    fn isFinalizedDescendant(self: *Self, blockRoot: types.Root) bool {
        const finalized_slot = self.fcStore.latest_finalized.slot;
        const finalized_root = self.fcStore.latest_finalized.root;

        var searched_idx_or_null = self.protoArray.indices.get(blockRoot);

        while (searched_idx_or_null) |searched_idx| {
            const searched_node_or_null: ?ProtoNode = self.protoArray.nodes.items[searched_idx];
            if (searched_node_or_null) |searched_node| {
                if (searched_node.slot <= finalized_slot) {
                    if (std.mem.eql(u8, searched_node.blockRoot[0..], finalized_root[0..])) {
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    searched_idx_or_null = searched_node.parent;
                }
            } else {
                break;
            }
        }

        return false;
    }

    /// Builds a canonical view hashmap containing all blocks in the canonical chain
    /// from targetAnchor back to prevAnchor, plus all their unfinalized descendants.
    pub fn getCanonicalView(self: *Self, canonical_view: *std.AutoHashMap(types.Root, void), targetAnchorRoot: types.Root, prevAnchorRootOrNull: ?types.Root) !void {
        const prev_anchor_idx = if (prevAnchorRootOrNull) |prevAnchorRoot| (self.protoArray.indices.get(prevAnchorRoot) orelse return ForkChoiceError.InvalidAnchor) else 0;
        const target_anchor_idx = self.protoArray.indices.get(targetAnchorRoot) orelse return ForkChoiceError.InvalidTargetAnchor;

        // first get all canonical blocks till previous anchors
        var current_idx = target_anchor_idx;
        while (current_idx >= prev_anchor_idx) {
            const current_node = self.protoArray.nodes.items[current_idx];
            try canonical_view.put(current_node.blockRoot, {});

            if (current_idx != prev_anchor_idx) {
                current_idx = current_node.parent orelse return ForkChoiceError.InvalidCanonicalTraversal;
                // extra soundness check
                if (current_idx < prev_anchor_idx) {
                    return ForkChoiceError.InvalidCanonicalTraversal;
                }
            } else {
                break;
            }
        }

        // add all the potential downstream canonical blocks to the map i.e. unfinalized descendants
        current_idx = target_anchor_idx + 1;
        while (current_idx < self.protoArray.nodes.items.len) {
            // if the parent of this node is already in the canonical_blocks, this is a potential canonical block
            const current_node = self.protoArray.nodes.items[current_idx];
            const parent_idx = current_node.parent orelse return ForkChoiceError.InvalidCanonicalTraversal;
            const parent_node = self.protoArray.nodes.items[parent_idx];
            // parent should be canonical but no parent should be before target anchor
            // because then it would be on a side branch to target anchor
            //
            // root=be35ab6546a38c4d5d42b588ac952867f19e03d1f12b4474f3b627db15739431 slot=30 index=7 parent=4 (arrived late)
            // root=35ba9cb9ea2e0e8d1248f40dc9d2142e0de2d18812be529ff024c7bcb5cd4b31 slot=31 index=5 parent=4
            // root=50ebab7c7948a768f298d9dc0b9863c0095d8df55f15e761b7eb032f3177ba6c slot=24 index=4 parent=3
            // root=c06f61119634e626d5e947ac7baaa8242b707a012880370875efeb2c0539ce7b slot=22 index=3 parent=2
            // root=57018d16f19782f832e8585657862930dd1acd217f308e60d23ad5a8efbb5f81 slot=21 index=2 parent=1
            // root=788b12ebd124982cc09433b1aadc655c7d876214ea2905f1b594564308c80e86 slot=20 index=1 parent=0
            // root=d754cf64f908c488eafc7453db7383be232a568f8e411c43bff809eb7a8e3028 slot=19 index=0 parent=null
            // targetAnchorRoot is 35ba9cb9ea2e0e8d1248f40dc9d2142e0de2d18812be529ff024c7bcb5cd4b31
            //
            // now without the parent index >= target_anchor_idx check slot=30 also ends up being added in canonical
            // because its parent is correctly canonical and has already been added to canonical_view in first while loop
            // however target anchor is slot=31 and hence slot=30 shouldn't be on a downstream unfinalized subtree
            //
            // test cases for the above are already present in the rebase testing

            if (parent_idx >= target_anchor_idx and canonical_view.contains(parent_node.blockRoot)) {
                try canonical_view.put(current_node.blockRoot, {});
            }
            current_idx += 1;
        }
    }

    /// Analyzes block canonicality relative to a target finalization anchor.
    /// Returns [canonical_roots, potential_canonical_roots, non_canonical_roots].
    ///
    /// SCOPE: Analysis is limited to blocks at or after prevAnchorRootOrNull (or genesis if null).
    /// Blocks before the previous anchor are considered stable and not analyzed.
    ///
    /// - canonical_roots: Blocks on the path from targetAnchor back to prevAnchor (slot <= target)
    /// - potential_canonical_roots: Descendants of canonical blocks with slot > target (unfinalized)
    /// - non_canonical_roots: Blocks not in the canonical set (orphans)
    ///
    /// If canonicalViewOrNull is provided, it reuses an existing canonical view for efficiency.
    pub fn getCanonicalityAnalysis(self: *Self, targetAnchorRoot: types.Root, prevAnchorRootOrNull: ?types.Root, canonicalViewOrNull: ?*std.AutoHashMap(types.Root, void)) ![3][]types.Root {
        var canonical_roots = std.ArrayList(types.Root).init(self.allocator);
        var potential_canonical_roots = std.ArrayList(types.Root).init(self.allocator);
        var non_canonical_roots = std.ArrayList(types.Root).init(self.allocator);

        // get some info about previous and target anchors
        const prev_anchor_idx = if (prevAnchorRootOrNull) |prevAnchorRoot| (self.protoArray.indices.get(prevAnchorRoot) orelse return ForkChoiceError.InvalidAnchor) else 0;
        const target_anchor_idx = self.protoArray.indices.get(targetAnchorRoot) orelse return ForkChoiceError.InvalidTargetAnchor;
        const target_anchor_slot = self.protoArray.nodes.items[target_anchor_idx].slot;

        // get all canonical view of the chain finalized and unfinalized anchored at the targetAnchorRoot
        var canonical_blocks = canonicalViewOrNull orelse blk: {
            var local_view = std.AutoHashMap(types.Root, void).init(self.allocator);
            try self.getCanonicalView(&local_view, targetAnchorRoot, prevAnchorRootOrNull);
            break :blk &local_view;
        };

        // now we can split forkchoice into 3 parts (excluding target anchor)
        // traversing all the way from the bottom to the prev_anchor_idx
        var current_idx = self.protoArray.nodes.items.len - 1;
        while (current_idx >= prev_anchor_idx) {
            const current_node = self.protoArray.nodes.items[current_idx];
            if (canonical_blocks.contains(current_node.blockRoot)) {
                if (current_node.slot <= target_anchor_slot) {
                    self.logger.debug("adding confirmed canonical root={s} slot={d} index={d} parent={any}", .{
                        std.fmt.fmtSliceHexLower(&current_node.blockRoot),
                        current_node.slot,
                        current_idx,
                        current_node.parent,
                    });
                    _ = try canonical_roots.append(current_node.blockRoot);
                } else if (current_node.slot > target_anchor_slot) {
                    _ = try potential_canonical_roots.append(current_node.blockRoot);
                }
            } else {
                _ = try non_canonical_roots.append(current_node.blockRoot);
            }
            if (current_idx == 0) {
                break;
            } else {
                current_idx -= 1;
            }
        }
        // confirm first root in canonical_roots is the new anchor because it should have been pushed first
        if (!std.mem.eql(u8, &canonical_roots.items[0], &targetAnchorRoot)) {
            for (canonical_roots.items, 0..) |root, index| {
                self.logger.err("canonical root at index={d} {s}", .{
                    index,
                    std.fmt.fmtSliceHexLower(&root),
                });
            }
            self.logger.err("targetAnchorRoot is {s}", .{std.fmt.fmtSliceHexLower(&targetAnchorRoot)});
            return ForkChoiceError.InvalidCanonicalTraversal;
        }

        const result = [_]([]types.Root){
            try canonical_roots.toOwnedSlice(),
            //
            try potential_canonical_roots.toOwnedSlice(),
            try non_canonical_roots.toOwnedSlice(),
        };

        // only way to conditionally deinit locally allocated map created in a orelse block scope
        if (canonicalViewOrNull == null) {
            canonical_blocks.deinit();
        }
        return result;
    }

    /// Rebases the forkchoice tree to a new anchor, pruning non-canonical blocks.
    pub fn rebase(self: *Self, targetAnchorRoot: types.Root, canonicalViewOrNull: ?*std.AutoHashMap(types.Root, void)) !void {
        const target_anchor_idx = self.protoArray.indices.get(targetAnchorRoot) orelse return ForkChoiceError.InvalidTargetAnchor;
        const target_anchor_slot = self.protoArray.nodes.items[target_anchor_idx].slot;

        var canonical_view = canonicalViewOrNull orelse blk: {
            var local_view = std.AutoHashMap(types.Root, void).init(self.allocator);
            try self.getCanonicalView(&local_view, targetAnchorRoot, null);
            break :blk &local_view;
        };

        // prune, interesting thing to note is the entire subtree of targetAnchorRoot is not affected and is to be
        // preserved as it is, because nothing from there is getting pruned
        var shifted_left: usize = 0;
        var old_indices_to_new = std.AutoHashMap(usize, usize).init(self.allocator);
        defer old_indices_to_new.deinit();

        var current_idx: usize = 0;
        while (current_idx < self.protoArray.nodes.items.len) {
            const current_node = self.protoArray.nodes.items[current_idx];
            // we preserve the tree all the way down from the target anchor and its unfinalized potential canonical descendants
            if (canonical_view.contains(current_node.blockRoot) and current_node.slot >= target_anchor_slot) {
                try self.protoArray.indices.put(current_node.blockRoot, current_idx);
                try old_indices_to_new.put((current_idx + shifted_left), current_idx);

                // go to the next node
                current_idx += 1;
            } else {
                // remove the node and continue back to the loop with updating current idx
                // because after removal next node would be referred at the same current idx
                _ = self.protoArray.nodes.orderedRemove(current_idx);
                // don't need order preserving on deltas as they are always set to zero before their use
                _ = self.deltas.swapRemove(current_idx);
                _ = self.protoArray.indices.remove(current_node.blockRoot);
                shifted_left += 1;
            }
        }

        // correct parent, bestChild and bestDescendant indices using the created old to new map
        current_idx = 0;
        while (current_idx < self.protoArray.nodes.items.len) {
            // fix parent
            var current_node = self.protoArray.nodes.items[current_idx];
            if (current_idx == 0) {
                current_node.parent = null;
            } else {
                // all other nodes should have parents, otherwise its an irrecoverable error as we have already
                // modified forkchoice and can't be restored
                const old_parent_idx = current_node.parent orelse @panic("invalid parent of the rebased unfinalized");
                const new_parent_idx = old_indices_to_new.get(old_parent_idx);
                current_node.parent = new_parent_idx;
            }

            // fix bestChild and descendant
            if (current_node.bestChild) |old_best_child_idx| {
                // we should be able to lookup new index otherwise its an irrecoverable error
                const new_best_child_idx = old_indices_to_new.get(old_best_child_idx) orelse @panic("invalid old index lookup for rebased best child");
                current_node.bestChild = new_best_child_idx;

                // best descendant should always be there when there is a best child
                const old_best_descendant_idx = current_node.bestDescendant orelse @panic("invalid forkchoice with null best descendant for a non null best child");
                // we should be able to lookup new index otherwise its an irrecoverable error
                const new_best_descendant_idx = old_indices_to_new.get(old_best_descendant_idx) orelse @panic("invalid old index lookup for rebase best descendant");
                current_node.bestDescendant = new_best_descendant_idx;
            } else {
                // confirm best descendant is also null
                if (current_node.bestDescendant != null) {
                    @panic("invalid forkchoice with non null best descendant but with null best child");
                }
            }
            self.protoArray.nodes.items[current_idx] = current_node;
            current_idx += 1;
        }

        // confirm the first entry in forkchoice is the target anchor
        if (!std.mem.eql(u8, &self.protoArray.nodes.items[0].blockRoot, &targetAnchorRoot)) {
            @panic("invalid forkchoice rebasing with forkchoice base not matching target anchor");
        }

        // cleanup the vote tracker and remove all the entries which are not in canonical
        var iterator = self.attestations.iterator();
        while (iterator.next()) |entry| {
            // fix applied index
            if (entry.value_ptr.appliedIndex) |applied_index| {
                const new_index_lookup = old_indices_to_new.get(applied_index);
                // this simple assignment suffices both for cases where new index is found i.e. is canonical
                // or not, in which case it needs to point to null
                entry.value_ptr.appliedIndex = new_index_lookup;
            }

            // fix latestKnown
            if (entry.value_ptr.latestKnown) |*latest_known| {
                const new_index_lookup = old_indices_to_new.get(latest_known.index);
                // if we find the index then update it else change it to null as it was non canonical
                if (new_index_lookup) |new_index| {
                    latest_known.index = new_index;
                } else {
                    entry.value_ptr.latestKnown = null;
                }
            }

            // fix latestNew
            if (entry.value_ptr.latestNew) |*latest_new| {
                const new_index_lookup = old_indices_to_new.get(latest_new.index);
                // if we find the index then update it else change it to null as it was non canonical
                if (new_index_lookup) |new_index| {
                    latest_new.index = new_index;
                } else {
                    entry.value_ptr.latestNew = null;
                }
            }
        }

        if (canonicalViewOrNull == null) {
            canonical_view.deinit();
        }
        return;
    }

    /// Returns the canonical ancestor at the specified depth from the current head.
    /// Depth 0 returns the head itself. Traverses parent pointers (not slot arithmetic),
    /// so missed slots don't affect depth counting. If depth exceeds chain length,
    /// clamps to genesis.
    pub fn getCanonicalAncestorAtDepth(self: *Self, min_depth: usize) !ProtoBlock {
        var depth = min_depth;
        var current_idx = self.protoArray.indices.get(self.head.blockRoot) orelse return ForkChoiceError.InvalidHeadIndex;

        // If depth exceeds chain length, clamp to genesis
        if (current_idx < depth) {
            current_idx = 0;
            depth = 0;
        }

        // Traverse parent pointers until we reach the requested depth or genesis.
        // This naturally handles missed slots since we follow parent links, not slot numbers.
        while (depth > 0 and current_idx > 0) {
            const current_node = self.protoArray.nodes.items[current_idx];
            current_idx = current_node.parent orelse return ForkChoiceError.InvalidCanonicalTraversal;
            depth -= 1;
        }

        const ancestor_at_depth = zeam_utils.Cast(ProtoBlock, self.protoArray.nodes.items[current_idx]);
        return ancestor_at_depth;
    }

    pub fn tickInterval(self: *Self, hasProposal: bool) !void {
        self.fcStore.time += 1;
        const currentInterval = self.fcStore.time % constants.INTERVALS_PER_SLOT;

        switch (currentInterval) {
            0 => {
                self.fcStore.timeSlots += 1;
                if (hasProposal) {
                    _ = try self.acceptNewAttestations();
                }
            },
            1 => {},
            2 => {
                _ = try self.updateSafeTarget();
            },
            3 => {
                _ = try self.acceptNewAttestations();
            },
            else => @panic("invalid interval"),
        }
        self.logger.debug("forkchoice ticked to time(intervals)={d} slot={d}", .{ self.fcStore.time, self.fcStore.timeSlots });
    }

    pub fn onInterval(self: *Self, time_intervals: usize, has_proposal: bool) !void {
        while (self.fcStore.time < time_intervals) {
            try self.tickInterval(has_proposal and (self.fcStore.time + 1) == time_intervals);
        }
    }

    pub fn acceptNewAttestations(self: *Self) !ProtoBlock {
        for (0..self.config.genesis.numValidators()) |validator_id| {
            var attestation_tracker = self.attestations.get(validator_id) orelse AttestationTracker{};
            if (attestation_tracker.latestNew) |new_attestation| {
                // we can directly assign because we always make sure that new attestation is fresher
                // than an onchain attestation by purging those which are earlier than those seen on chain
                attestation_tracker.latestKnown = new_attestation;
            }

            try self.attestations.put(validator_id, attestation_tracker);
        }

        return self.updateHead();
    }

    pub fn getProposalHead(self: *Self, slot: types.Slot) !types.Checkpoint {
        const time_intervals = slot * constants.INTERVALS_PER_SLOT;
        // this could be called independently by the validator when its a separate process
        // and FC would need to be protected by mutex to make it thread safe but for now
        // this is deterministally called after the fc has been ticked ahead
        // so the following call should be a no-op
        try self.onInterval(time_intervals, true);
        // accept any new attestations in case previous ontick was a no-op and either the validator
        // wasn't registered or there have been new attestations
        const head = try self.acceptNewAttestations();

        return types.Checkpoint{
            .root = head.blockRoot,
            .slot = head.slot,
        };
    }

    pub fn getProposalAttestations(self: *Self) ![]types.Attestation {
        var included_attestations = std.ArrayList(types.Attestation).init(self.allocator);
        const latest_justified = self.fcStore.latest_justified;

        // TODO naive strategy to include all attestations that are consistent with the latest justified
        // replace by the other mini 3sf simple strategy to loop and see if justification happens and
        // till no further attestations can be added
        for (0..self.config.genesis.numValidators()) |validator_id| {
            const attestation_data = ((self.attestations.get(validator_id) orelse AttestationTracker{})
                //
                .latestKnown orelse ProtoAttestation{}).attestation_data;

            if (attestation_data) |att_data| {
                if (std.mem.eql(u8, &latest_justified.root, &att_data.source.root)) {
                    const attestation = types.Attestation{
                        .data = att_data,
                        .validator_id = @intCast(validator_id),
                    };
                    try included_attestations.append(attestation);
                }
            }
        }
        return included_attestations.toOwnedSlice();
    }

    pub fn getAttestationTarget(self: *Self) !types.Checkpoint {
        var target_idx = self.protoArray.indices.get(self.head.blockRoot) orelse return ForkChoiceError.InvalidHeadIndex;
        const nodes = self.protoArray.nodes.items;

        for (0..3) |i| {
            _ = i;
            if (nodes[target_idx].slot > self.safeTarget.slot) {
                target_idx = nodes[target_idx].parent orelse return ForkChoiceError.InvalidTargetSearch;
            }
        }

        while (!try types.IsJustifiableSlot(self.fcStore.latest_finalized.slot, nodes[target_idx].slot)) {
            target_idx = nodes[target_idx].parent orelse return ForkChoiceError.InvalidTargetSearch;
        }

        // Ensure target is at or after the source (latest_justified) to maintain invariant: source.slot <= target.slot
        // This prevents creating invalid attestations where source slot exceeds target slot
        // If the calculated target is older than latest_justified, use latest_justified instead
        if (nodes[target_idx].slot < self.fcStore.latest_justified.slot) {
            return self.fcStore.latest_justified;
        }

        return types.Checkpoint{
            .root = nodes[target_idx].blockRoot,
            .slot = nodes[target_idx].slot,
        };
    }

    pub fn computeDeltas(self: *Self, from_known: bool) ![]isize {
        // prep the deltas data structure
        while (self.deltas.items.len < self.protoArray.nodes.items.len) {
            try self.deltas.append(0);
        }
        for (0..self.deltas.items.len) |i| {
            self.deltas.items[i] = 0;
        }
        // balances are right now same for the dummy chain and each weighing 1
        const validatorWeight = 1;

        for (0..self.config.genesis.numValidators()) |validator_id| {
            var attestation_tracker = self.attestations.get(validator_id) orelse AttestationTracker{};
            if (attestation_tracker.appliedIndex) |applied_index| {
                self.deltas.items[applied_index] -= validatorWeight;
            }
            attestation_tracker.appliedIndex = null;

            // new index could be null if validator exits from the state
            // we don't need to null the new index after application because
            // applied and new will be same will no impact but this could still be a
            // relevant operation if/when the validator weight changes
            const latest_attestation = if (from_known) attestation_tracker.latestKnown else attestation_tracker.latestNew;
            if (latest_attestation) |delta_attestation| {
                self.deltas.items[delta_attestation.index] += validatorWeight;
                attestation_tracker.appliedIndex = delta_attestation.index;
            }
            try self.attestations.put(validator_id, attestation_tracker);
        }

        return self.deltas.items;
    }

    pub fn computeFCHead(self: *Self, from_known: bool, cutoff_weight: u64) !ProtoBlock {
        const deltas = try self.computeDeltas(from_known);
        try self.protoArray.applyDeltas(deltas, cutoff_weight);

        // head is the best descendant of latest justified
        const justified_idx = self.protoArray.indices.get(self.fcStore.latest_justified.root) orelse return ForkChoiceError.InvalidJustifiedRoot;
        const justified_node = self.protoArray.nodes.items[justified_idx];

        // if case of no best descendant latest justified is always best descendant
        const best_descendant_idx = justified_node.bestDescendant orelse justified_idx;
        const best_descendant = self.protoArray.nodes.items[best_descendant_idx];

        self.logger.debug("computeFCHead from_known={} cutoff_weight={d} deltas={any} justified_node={any} best_descendant_idx={d}", .{
            //
            from_known,
            cutoff_weight,
            deltas,
            justified_node,
            best_descendant_idx,
        });

        const fcHead = zeam_utils.Cast(ProtoBlock, best_descendant);
        return fcHead;
    }

    pub fn updateHead(self: *Self) !ProtoBlock {
        const previous_head = self.head;
        self.head = try self.computeFCHead(true, 0);

        // Update the lean_head_slot metric
        zeam_metrics.metrics.lean_head_slot.set(self.head.slot);

        // Detect reorg: if head changed and previous head is not an ancestor of new head
        if (!std.mem.eql(u8, &self.head.blockRoot, &previous_head.blockRoot)) {
            // Build ancestor map while checking - reused in calculateReorgDepth if reorg detected
            var new_head_ancestors = std.AutoHashMap(types.Root, void).init(self.allocator);
            defer new_head_ancestors.deinit();

            const is_extension = self.isAncestorOf(previous_head.blockRoot, self.head.blockRoot, &new_head_ancestors);
            if (!is_extension) {
                // Reorg detected - previous head is NOT an ancestor of new head
                const depth = self.calculateReorgDepth(previous_head.blockRoot, &new_head_ancestors);
                zeam_metrics.metrics.lean_fork_choice_reorgs_total.incr();
                zeam_metrics.metrics.lean_fork_choice_reorg_depth.observe(@floatFromInt(depth));
                self.logger.info("fork choice reorg detected: depth={d} old_head_slot={d} new_head_slot={d}", .{
                    depth,
                    previous_head.slot,
                    self.head.slot,
                });
            }
        }

        return self.head;
    }

    /// Checks if potential_ancestor is an ancestor of descendant by walking up parent chain.
    /// Populates ancestors_map with all visited nodes for reuse in calculateReorgDepth.
    /// Note: descendant must exist in protoArray (it comes from computeFCHead which retrieves
    /// it directly from protoArray.nodes). If not found, it indicates a bug in the code.
    fn isAncestorOf(self: *Self, potential_ancestor: types.Root, descendant: types.Root, ancestors_map: *std.AutoHashMap(types.Root, void)) bool {
        // descendant is guaranteed to exist - it comes from computeFCHead() which
        // retrieves it directly from protoArray.nodes.
        var maybe_idx: ?usize = self.protoArray.indices.get(descendant);
        if (maybe_idx == null) unreachable; // invariant violation - descendant must exist

        while (maybe_idx) |idx| {
            const current_node = self.protoArray.nodes.items[idx];
            ancestors_map.put(current_node.blockRoot, {}) catch {};
            if (std.mem.eql(u8, &current_node.blockRoot, &potential_ancestor)) {
                return true;
            }
            maybe_idx = current_node.parent;
        }
        return false;
    }

    /// Calculate the reorg depth by counting blocks from old head to common ancestor.
    /// Uses pre-built new_head_ancestors map from isAncestorOf to avoid redundant traversal.
    fn calculateReorgDepth(self: *Self, old_head_root: types.Root, new_head_ancestors: *std.AutoHashMap(types.Root, void)) usize {
        // Walk up from old head counting blocks until we hit a common ancestor
        // old_head_root could potentially be pruned in edge cases, so use defensive return 0
        var depth: usize = 0;
        var maybe_old_idx: ?usize = self.protoArray.indices.get(old_head_root);
        if (maybe_old_idx == null) return 0; // defensive - old head could be pruned

        while (maybe_old_idx) |idx| {
            const old_node = self.protoArray.nodes.items[idx];
            if (new_head_ancestors.contains(old_node.blockRoot)) {
                return depth;
            }
            depth += 1;
            maybe_old_idx = old_node.parent;
        }
        return depth;
    }

    pub fn updateSafeTarget(self: *Self) !ProtoBlock {
        const cutoff_weight = try std.math.divCeil(u64, 2 * self.config.genesis.numValidators(), 3);
        self.safeTarget = try self.computeFCHead(false, cutoff_weight);
        // Update safe target slot metric
        zeam_metrics.metrics.lean_safe_target_slot.set(self.safeTarget.slot);
        return self.safeTarget;
    }

    pub fn onGossipAttestation(self: *Self, signed_attestation: types.SignedAttestation, is_from_block: bool) !void {
        // Attestation validation is done by the caller (chain layer)
        // This function assumes the attestation has already been validated

        // attestation has to be of an ancestor of the current slot
        const attestation_data = signed_attestation.message;
        const validator_id = signed_attestation.validator_id;
        const attestation_slot = attestation_data.slot;

        // Store the gossip signature for later lookup during block building
        const data_root = try attestation_data.sszRoot(self.allocator);
        const sig_key = SignatureKey{
            .validator_id = validator_id,
            .data_root = data_root,
        };
        try self.gossip_signatures.put(sig_key, .{
            .slot = attestation_slot,
            .signature = signed_attestation.signature,
        });

        const attestation = types.Attestation{
            .data = attestation_data,
            .validator_id = validator_id,
        };

        try self.onAttestation(attestation, is_from_block);
    }

    pub fn onAttestation(self: *Self, attestation: types.Attestation, is_from_block: bool) !void {
        const attestation_data = attestation.data;
        const validator_id = attestation.validator_id;
        const attestation_slot = attestation_data.slot;

        // This get should never fail after validation, but we keep the check for safety
        const new_head_index = self.protoArray.indices.get(attestation_data.head.root) orelse {
            // Track whether this is from gossip or block processing
            return ForkChoiceError.InvalidAttestation;
        };

        var attestation_tracker = self.attestations.get(validator_id) orelse AttestationTracker{};
        // update latest known attested head of the validator if already included on chain
        if (is_from_block) {
            const attestation_tracker_latest_known_slot = (attestation_tracker.latestKnown orelse ProtoAttestation{}).slot;
            if (attestation_slot > attestation_tracker_latest_known_slot) {
                attestation_tracker.latestKnown = .{
                    .index = new_head_index,
                    .slot = attestation_slot,
                    .attestation_data = attestation_data,
                };
            }

            // also clear out our latest new non included attestation if this is even later than that
            const attestation_tracker_latest_new_slot = (attestation_tracker.latestNew orelse ProtoAttestation{}).slot;
            if (attestation_slot > attestation_tracker_latest_new_slot) {
                attestation_tracker.latestNew = null;
            }
        } else {
            if (attestation_slot > self.fcStore.timeSlots) {
                return ForkChoiceError.InvalidFutureAttestation;
            }
            // just update latest new attested head of the validator
            const attestation_tracker_latest_new_slot = (attestation_tracker.latestNew orelse ProtoAttestation{}).slot;
            if (attestation_slot > attestation_tracker_latest_new_slot) {
                attestation_tracker.latestNew = .{
                    .index = new_head_index,
                    .slot = attestation_slot,
                    .attestation_data = attestation_data,
                };
            }
        }
        try self.attestations.put(validator_id, attestation_tracker);
    }

    /// Store an aggregated signature proof for a validator from a block.
    /// This allows future block builders to reuse this aggregation.
    pub fn storeAggregatedPayload(
        self: *Self,
        validator_id: types.ValidatorIndex,
        attestation_data: *const types.AttestationData,
        proof: types.AggregatedSignatureProof,
    ) !void {
        const data_root = try attestation_data.sszRoot(self.allocator);
        const sig_key = SignatureKey{
            .validator_id = validator_id,
            .data_root = data_root,
        };

        // Get or create the list for this key
        const gop = try self.aggregated_payloads.getOrPut(sig_key);
        if (!gop.found_existing) {
            gop.value_ptr.* = AggregatedPayloadsList.init(self.allocator);
        }
        try gop.value_ptr.append(.{
            .slot = attestation_data.slot,
            .proof = proof,
        });
    }

    /// Prune gossip_signatures and aggregated_payloads for attestations at or before the finalized slot.
    /// This is called after finalization to clean up signature data that is no longer needed.
    pub fn pruneSignatureMaps(self: *Self, finalized_slot: types.Slot) !void {
        var gossip_keys_to_remove = std.ArrayList(SignatureKey).init(self.allocator);
        defer gossip_keys_to_remove.deinit();

        var payload_keys_to_remove = std.ArrayList(SignatureKey).init(self.allocator);
        defer payload_keys_to_remove.deinit();

        var gossip_removed: usize = 0;
        var payloads_removed: usize = 0;

        // Identify gossip signatures that are at or before the finalized slot
        var gossip_it = self.gossip_signatures.iterator();
        while (gossip_it.next()) |entry| {
            if (entry.value_ptr.slot <= finalized_slot) {
                try gossip_keys_to_remove.append(entry.key_ptr.*);
            }
        }

        for (gossip_keys_to_remove.items) |sig_key| {
            if (self.gossip_signatures.remove(sig_key)) {
                gossip_removed += 1;
            }
        }

        // Prune aggregated payload proofs by slot as well
        var payload_it = self.aggregated_payloads.iterator();
        while (payload_it.next()) |entry| {
            var list = entry.value_ptr;
            var write_index: usize = 0;
            var removed_here: usize = 0;

            for (list.items) |*stored| {
                if (stored.slot <= finalized_slot) {
                    stored.proof.deinit();
                    removed_here += 1;
                } else {
                    list.items[write_index] = stored.*;
                    write_index += 1;
                }
            }

            if (removed_here > 0) {
                payloads_removed += removed_here;
                list.items = list.items[0..write_index];
            }

            if (list.items.len == 0) {
                try payload_keys_to_remove.append(entry.key_ptr.*);
            }
        }

        for (payload_keys_to_remove.items) |sig_key| {
            if (self.aggregated_payloads.fetchRemove(sig_key)) |kv| {
                kv.value.deinit();
            }
        }

        if (gossip_removed > 0 or payloads_removed > 0) {
            self.logger.debug("pruned signature maps: gossip_signatures={d} aggregated_payload_proofs={d} for finalized_slot={d}", .{
                gossip_removed,
                payloads_removed,
                finalized_slot,
            });
        }
    }

    // we process state outside forkchoice onblock to parallize verifications and just use the post state here
    pub fn onBlock(self: *Self, block: types.BeamBlock, state: *const types.BeamState, opts: OnBlockOpts) !ProtoBlock {
        const parent_root = block.parent_root;
        const slot = block.slot;

        const parent_block_or_null = self.getBlock(parent_root);
        if (parent_block_or_null) |parent_block| {
            // we will use parent block later as per the finalization gadget
            _ = parent_block;

            if (slot * constants.INTERVALS_PER_SLOT > self.fcStore.time) {
                return ForkChoiceError.FutureSlot;
            } else if (slot < self.fcStore.latest_finalized.slot) {
                return ForkChoiceError.PreFinalizedSlot;
            }

            const is_finalized_descendant = self.isFinalizedDescendant(parent_root);
            if (is_finalized_descendant != true) {
                return ForkChoiceError.NotFinalizedDesendant;
            }

            const justified = state.latest_justified;
            const finalized = state.latest_finalized;
            self.fcStore.update(justified, finalized);

            const block_root: [32]u8 = opts.blockRoot orelse computedroot: {
                var cblock_root: [32]u8 = undefined;
                try ssz.hashTreeRoot(types.BeamBlock, block, &cblock_root, self.allocator);
                break :computedroot cblock_root;
            };
            const is_timely = self.isBlockTimely(opts.blockDelayMs);

            const proto_block = ProtoBlock{
                .slot = slot,
                .blockRoot = block_root,
                .parentRoot = parent_root,
                .stateRoot = block.state_root,
                .timeliness = is_timely,
                .confirmed = opts.confirmed,
            };

            try self.protoArray.onBlock(proto_block, opts.currentSlot);
            return proto_block;
        } else {
            return ForkChoiceError.UnknownParent;
        }
    }

    pub fn confirmBlock(self: *Self, blockRoot: types.Root) !void {
        if (self.protoArray.indices.get(blockRoot)) |block_idx| {
            self.protoArray.nodes.items[block_idx].confirmed = true;
        } else {
            return ForkChoiceError.InvalidForkchoiceBlock;
        }
    }

    pub fn hasBlock(self: *Self, blockRoot: types.Root) bool {
        const block_or_null = self.getBlock(blockRoot);
        // we can only say we have the block if its fully confirmed to be imported
        if (block_or_null) |block| {
            return (block.confirmed == true);
        }

        return false;
    }

    pub fn getBlock(self: *Self, blockRoot: types.Root) ?ProtoBlock {
        const nodeOrNull = self.protoArray.getNode(blockRoot);
        if (nodeOrNull) |node| {
            // TODO cast doesn't seem to be working find resolution
            // const block = utils.Cast(ProtoBlock, node);
            const block = ProtoBlock{
                .slot = node.slot,
                .blockRoot = node.blockRoot,
                .parentRoot = node.parentRoot,
                .stateRoot = node.stateRoot,
                .timeliness = node.timeliness,
                .confirmed = node.confirmed,
            };
            return block;
        } else {
            return null;
        }
    }
};

pub const ForkChoiceError = error{
    NotImplemented,
    UnknownParent,
    FutureSlot,
    InvalidFutureAttestation,
    InvalidOnChainAttestation,
    PreFinalizedSlot,
    NotFinalizedDesendant,
    InvalidAttestation,
    InvalidDeltas,
    InvalidJustifiedRoot,
    InvalidBestDescendant,
    InvalidHeadIndex,
    InvalidTargetSearch,
    InvalidAnchor,
    InvalidTargetAnchor,
    InvalidCanonicalTraversal,
    InvalidForkchoiceBlock,
};

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_pubkeys instead of num_validators
test "forkchoice block tree" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Use genMockChain with null to generate default genesis with pubkeys
    const mock_chain = try stf.genMockChain(allocator, 2, null);

    // Create chain config from mock chain genesis
    const spec_name = try allocator.dupe(u8, "beamdev");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
        },
    };
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.forkchoice);
    var fork_choice = try ForkChoice.init(allocator, .{
        .config = chain_config,
        .anchorState = &beam_state,
        .logger = module_logger,
    });

    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.latest_finalized.root, &mock_chain.blockRoots[0]));
    try std.testing.expect(fork_choice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.latest_finalized.root, &fork_choice.protoArray.nodes.items[0].blockRoot));
    try std.testing.expect(std.mem.eql(u8, mock_chain.blocks[0].message.block.state_root[0..], &fork_choice.protoArray.nodes.items[0].stateRoot));
    try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[0], &fork_choice.protoArray.nodes.items[0].blockRoot));

    for (1..mock_chain.blocks.len) |i| {
        // get the block post state
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.message.block;
        try stf.apply_transition(allocator, &beam_state, block, .{ .logger = module_logger });

        // shouldn't accept a future slot
        const current_slot = block.slot;
        try std.testing.expectError(error.FutureSlot, fork_choice.onBlock(block, &beam_state, .{ .currentSlot = current_slot, .blockDelayMs = 0, .confirmed = true }));

        try fork_choice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        _ = try fork_choice.onBlock(block, &beam_state, .{ .currentSlot = block.slot, .blockDelayMs = 0, .confirmed = true });
        try std.testing.expect(fork_choice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &fork_choice.protoArray.nodes.items[i].blockRoot));

        const searched_idx = fork_choice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);
    }
}

// Helper function to create a deterministic test root filled with a specific byte
fn createTestRoot(fill_byte: u8) types.Root {
    var root: types.Root = undefined;
    @memset(&root, fill_byte);
    return root;
}

// Helper function to create a ProtoBlock for testing
fn createTestProtoBlock(slot: types.Slot, block_root_byte: u8, parent_root_byte: u8) ProtoBlock {
    return ProtoBlock{
        .slot = slot,
        .blockRoot = createTestRoot(block_root_byte),
        .parentRoot = createTestRoot(parent_root_byte),
        .stateRoot = createTestRoot(0x00),
        .timeliness = true,
        .confirmed = true,
    };
}

test "getCanonicalAncestorAtDepth and getCanonicalityAnalysis" {
    // ============================================================================
    // COMPREHENSIVE TEST TREE
    // ============================================================================
    //
    // This test creates a single tree that exercises ALL key scenarios:
    //   1. FORKS      - Multiple children from one parent (C has children D and G)
    //   2. MISSED SLOTS - Gaps in slot numbers (slots 2, 4, 7 have no blocks)
    //   3. ORPHANS    - Non-canonical blocks that get pruned (G, H, I when finalized past C)
    //
    // Tree Structure:
    //
    //   Slot:  0      1      3      5      6      8
    //         [A] -> [B] -> [C] -> [D] -> [E] -> [F]    <- Canonical chain (head)
    //                        \
    //                         [G] -> [H] -> [I]         <- Fork branch (becomes orphans)
    //                        (s4)   (s6)   (s7)
    //
    //   Missed slots: 2, 4 (on canonical), 7
    //
    // Block Details:
    //   A = 0xAA (slot 0, genesis)
    //   B = 0xBB (slot 1, parent A)
    //   C = 0xCC (slot 3, parent B)     <- FORK POINT, missed slot 2
    //   D = 0xDD (slot 5, parent C)     <- missed slot 4 on canonical
    //   E = 0xEE (slot 6, parent D)
    //   F = 0xFF (slot 8, parent E)     <- HEAD, missed slot 7
    //   G = 0x11 (slot 4, parent C)     <- FORK starts here
    //   H = 0x22 (slot 6, parent G)
    //   I = 0x33 (slot 7, parent H)
    //
    // Node indices in protoArray:
    //   A=0, B=1, C=2, D=3, E=4, F=5, G=6, H=7, I=8
    //
    // ============================================================================

    const allocator = std.testing.allocator;

    var mock_chain = try stf.genMockChain(allocator, 2, null);
    defer mock_chain.deinit(allocator);

    const spec_name = try allocator.dupe(u8, "beamdev");
    defer allocator.free(spec_name);
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
        },
    };

    var beam_state = mock_chain.genesis_state;
    defer beam_state.deinit();
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.forkchoice);

    // ========================================
    // BUILD THE COMPREHENSIVE TREE
    // ========================================

    // Genesis block A at slot 0
    const anchor_block = createTestProtoBlock(0, 0xAA, 0x00);
    var proto_array = try ProtoArray.init(allocator, anchor_block);
    defer proto_array.nodes.deinit();
    defer proto_array.indices.deinit();

    // Canonical chain with missed slots
    try proto_array.onBlock(createTestProtoBlock(1, 0xBB, 0xAA), 1); // B: slot 1
    try proto_array.onBlock(createTestProtoBlock(3, 0xCC, 0xBB), 3); // C: slot 3 (missed slot 2)
    try proto_array.onBlock(createTestProtoBlock(5, 0xDD, 0xCC), 5); // D: slot 5 (missed slot 4)
    try proto_array.onBlock(createTestProtoBlock(6, 0xEE, 0xDD), 6); // E: slot 6
    try proto_array.onBlock(createTestProtoBlock(8, 0xFF, 0xEE), 8); // F: slot 8 (missed slot 7) - HEAD

    // Fork branch from C (with its own missed slots pattern)
    try proto_array.onBlock(createTestProtoBlock(4, 0x11, 0xCC), 4); // G: slot 4, parent C
    try proto_array.onBlock(createTestProtoBlock(6, 0x22, 0x11), 6); // H: slot 6, parent G (missed slot 5)
    try proto_array.onBlock(createTestProtoBlock(7, 0x33, 0x22), 7); // I: slot 7, parent H

    // Verify we have 9 nodes total
    try std.testing.expect(proto_array.nodes.items.len == 9);

    // Verify parent relationships
    try std.testing.expect(proto_array.nodes.items[1].parent == 0); // B -> A
    try std.testing.expect(proto_array.nodes.items[2].parent == 1); // C -> B
    try std.testing.expect(proto_array.nodes.items[3].parent == 2); // D -> C
    try std.testing.expect(proto_array.nodes.items[6].parent == 2); // G -> C (fork!)

    // Create ForkChoice with head at F
    const anchorCP = types.Checkpoint{ .slot = 0, .root = createTestRoot(0xAA) };
    const fc_store = ForkChoiceStore{
        .time = 8 * constants.INTERVALS_PER_SLOT,
        .timeSlots = 8,
        .latest_justified = anchorCP,
        .latest_finalized = anchorCP,
    };

    var fork_choice = ForkChoice{
        .allocator = allocator,
        .protoArray = proto_array,
        .anchorState = &beam_state,
        .config = chain_config,
        .fcStore = fc_store,
        .attestations = std.AutoHashMap(usize, AttestationTracker).init(allocator),
        .head = createTestProtoBlock(8, 0xFF, 0xEE), // Head is F
        .safeTarget = createTestProtoBlock(8, 0xFF, 0xEE),
        .deltas = std.ArrayList(isize).init(allocator),
        .logger = module_logger,
        .gossip_signatures = SignaturesMap.init(allocator),
        .aggregated_payloads = AggregatedPayloadsMap.init(allocator),
    };
    defer fork_choice.attestations.deinit();
    defer fork_choice.deltas.deinit();
    defer fork_choice.gossip_signatures.deinit();
    defer fork_choice.aggregated_payloads.deinit();

    // ========================================
    // TEST getCanonicalAncestorAtDepth
    // ========================================
    // Tests that depth traversal works correctly with missed slots
    // (follows parent pointers, not slot arithmetic)

    // Depth 0: Should return head F (slot 8)
    {
        const ancestor = try fork_choice.getCanonicalAncestorAtDepth(0);
        try std.testing.expect(ancestor.slot == 8);
        try std.testing.expect(std.mem.eql(u8, &ancestor.blockRoot, &createTestRoot(0xFF)));
    }

    // Depth 1: F -> E (slot 6), NOT slot 7 (which is missed on canonical)
    {
        const ancestor = try fork_choice.getCanonicalAncestorAtDepth(1);
        try std.testing.expect(ancestor.slot == 6);
        try std.testing.expect(std.mem.eql(u8, &ancestor.blockRoot, &createTestRoot(0xEE)));
    }

    // Depth 2: F -> E -> D (slot 5)
    {
        const ancestor = try fork_choice.getCanonicalAncestorAtDepth(2);
        try std.testing.expect(ancestor.slot == 5);
        try std.testing.expect(std.mem.eql(u8, &ancestor.blockRoot, &createTestRoot(0xDD)));
    }

    // Depth 3: F -> E -> D -> C (slot 3), skipping missed slot 4
    {
        const ancestor = try fork_choice.getCanonicalAncestorAtDepth(3);
        try std.testing.expect(ancestor.slot == 3);
        try std.testing.expect(std.mem.eql(u8, &ancestor.blockRoot, &createTestRoot(0xCC)));
    }

    // Depth 4: F -> E -> D -> C -> B (slot 1), skipping missed slot 2
    {
        const ancestor = try fork_choice.getCanonicalAncestorAtDepth(4);
        try std.testing.expect(ancestor.slot == 1);
        try std.testing.expect(std.mem.eql(u8, &ancestor.blockRoot, &createTestRoot(0xBB)));
    }

    // Depth 5: Returns genesis A (slot 0)
    {
        const ancestor = try fork_choice.getCanonicalAncestorAtDepth(5);
        try std.testing.expect(ancestor.slot == 0);
        try std.testing.expect(std.mem.eql(u8, &ancestor.blockRoot, &createTestRoot(0xAA)));
    }

    // Depth 100: Exceeds chain, clamps to genesis
    {
        const ancestor = try fork_choice.getCanonicalAncestorAtDepth(100);
        try std.testing.expect(ancestor.slot == 0);
        try std.testing.expect(std.mem.eql(u8, &ancestor.blockRoot, &createTestRoot(0xAA)));
    }

    // ========================================
    // TEST getCanonicalityAnalysis
    // ========================================

    // Test 1: Finalize to C (fork point), prev=A
    // G forks from C, so G's parent C is still canonical
    // All fork blocks have slot > C.slot(3), so they're potential canonical
    {
        const result = try fork_choice.getCanonicalityAnalysis(
            createTestRoot(0xCC), // target = C (slot 3)
            createTestRoot(0xAA), // prev = A
            null, // canonicalViewOrNull
        );
        defer allocator.free(result[0]);
        defer allocator.free(result[1]);
        defer allocator.free(result[2]);

        const canonical = result[0];
        const potential = result[1];
        const orphans = result[2];

        // Canonical: C, B, A (path from C to A, all with slot <= 3)
        try std.testing.expect(canonical.len == 3);
        try std.testing.expect(std.mem.eql(u8, &canonical[0], &createTestRoot(0xCC)));

        // Potential: D, E, F (canonical descendants) + G, H, I (fork descendants)
        // All have slot > 3
        try std.testing.expect(potential.len == 6);

        // No orphans (all blocks descend from canonical chain)
        try std.testing.expect(orphans.len == 0);
    }

    // Test 2: Finalize to E (slot 6), prev=C
    // E is target, path from E to C is canonical
    // G's parent C is in canonical, and G.slot(4) <= E.slot(6), so G is also canonical
    // BUT H.slot(6) <= E.slot(6), so H is also canonical!
    // However, since G and H have higher indices than E, they appear first - this triggers validation error
    // So we skip this edge case and use prev=D instead to get orphans
    //
    // Test 2: Finalize to F (slot 8), prev=E
    // This ensures fork blocks G, H, I have slots < F.slot but their parent chain
    // doesn't include E, so they become orphans
    {
        const result = try fork_choice.getCanonicalityAnalysis(
            createTestRoot(0xFF), // target = F (slot 8)
            createTestRoot(0xEE), // prev = E (slot 6)
            null, // canonicalViewOrNull
        );
        defer allocator.free(result[0]);
        defer allocator.free(result[1]);
        defer allocator.free(result[2]);

        const canonical = result[0];
        const potential = result[1];
        const orphans = result[2];

        // Canonical path: F, E only (from F back to E)
        try std.testing.expect(canonical.len == 2);
        try std.testing.expect(std.mem.eql(u8, &canonical[0], &createTestRoot(0xFF)));

        // No potential (F is head, nothing after it)
        try std.testing.expect(potential.len == 0);

        // Orphans: G, H, I (parent C not in canonical path E->F)
        try std.testing.expect(orphans.len == 3);
    }

    // Test 3: Finalize to D (slot 5), prev=D (same anchor)
    // This simulates incremental finalization where prev and target are same
    // Only D is canonical, G's parent C is NOT in canonical_blocks
    {
        const result = try fork_choice.getCanonicalityAnalysis(
            createTestRoot(0xDD), // target = D
            createTestRoot(0xDD), // prev = D (same!)
            null, // canonicalViewOrNull
        );
        defer allocator.free(result[0]);
        defer allocator.free(result[1]);
        defer allocator.free(result[2]);

        const canonical = result[0];
        const potential = result[1];
        const orphans = result[2];

        // Canonical: only D
        try std.testing.expect(canonical.len == 1);
        try std.testing.expect(std.mem.eql(u8, &canonical[0], &createTestRoot(0xDD)));

        // Potential: E, F (descendants of D)
        try std.testing.expect(potential.len == 2);

        // Orphans: G, H, I (parent C not in canonical_blocks since we only have D)
        try std.testing.expect(orphans.len == 3);

        // Verify orphans are the fork blocks
        var found_G = false;
        var found_H = false;
        var found_I = false;
        for (orphans) |root| {
            if (std.mem.eql(u8, &root, &createTestRoot(0x11))) found_G = true;
            if (std.mem.eql(u8, &root, &createTestRoot(0x22))) found_H = true;
            if (std.mem.eql(u8, &root, &createTestRoot(0x33))) found_I = true;
        }
        try std.testing.expect(found_G and found_H and found_I);
    }

    // Test 4: Finalize to E (slot 6), prev=D
    // D->E is canonical path, G's parent C is NOT included
    {
        const result = try fork_choice.getCanonicalityAnalysis(
            createTestRoot(0xEE), // target = E (slot 6)
            createTestRoot(0xDD), // prev = D
            null, // canonicalViewOrNull
        );
        defer allocator.free(result[0]);
        defer allocator.free(result[1]);
        defer allocator.free(result[2]);

        const canonical = result[0];
        const potential = result[1];
        const orphans = result[2];

        // Canonical: E, D (path from E to D)
        // G.slot(4) <= E.slot(6), but G's parent C is NOT in canonical_blocks
        try std.testing.expect(canonical.len == 2);
        try std.testing.expect(std.mem.eql(u8, &canonical[0], &createTestRoot(0xEE)));

        // Potential: F (slot 8 > 6)
        try std.testing.expect(potential.len == 1);

        // Orphans: G, H, I (parent C not in canonical_blocks)
        try std.testing.expect(orphans.len == 3);
    }

    // Test 5: Test with null prev anchor (defaults to genesis index 0)
    // Use target=C (slot 3) so G.slot(4) > target_slot, making G potential not canonical
    {
        const result = try fork_choice.getCanonicalityAnalysis(
            createTestRoot(0xCC), // target = C (slot 3)
            null, // prev = null (defaults to index 0 = A)
            null, // canonicalViewOrNull
        );
        defer allocator.free(result[0]);
        defer allocator.free(result[1]);
        defer allocator.free(result[2]);

        const canonical = result[0];
        const potential = result[1];

        // Should include full path: C, B, A
        try std.testing.expect(canonical.len == 3);
        try std.testing.expect(std.mem.eql(u8, &canonical[0], &createTestRoot(0xCC)));

        // Potential should include D, E, F (canonical descendants) + G, H, I (fork)
        try std.testing.expect(potential.len == 6);
    }
}

// ============================================================================
// REBASE FUNCTION TESTS
// ============================================================================
//
// These tests validate the rebase function's correctness across:
// 1. Node Relationship Integrity (parent, bestChild, bestDescendant)
// 2. Weight Preservation
// 3. Attestation Vote Tracker Integrity
// 4. Edge Cases
//
// Test Tree Structure (reused from getCanonicalityAnalysis test):
//
//   Slot:  0      1      3      5      6      8
//         [A] -> [B] -> [C] -> [D] -> [E] -> [F]    <- Canonical chain (head)
//                        \
//                         [G] -> [H] -> [I]         <- Fork branch (orphans)
//                        (s4)   (s6)   (s7)
//
//   Node indices: A=0, B=1, C=2, D=3, E=4, F=5, G=6, H=7, I=8
//   Missed slots: 2, 4 (on canonical), 7
// ============================================================================

// Helper function to create a SignedAttestation for testing
fn createTestSignedAttestation(validator_id: usize, head_root: types.Root, slot: types.Slot) types.SignedAttestation {
    return types.SignedAttestation{
        .validator_id = @intCast(validator_id),
        .message = .{
            .slot = slot,
            .head = .{ .root = head_root, .slot = slot },
            .target = .{ .root = head_root, .slot = slot },
            .source = .{ .root = createTestRoot(0xAA), .slot = 0 },
        },
        .signature = ZERO_SIGBYTES,
    };
}

// Helper to build the comprehensive test tree with 9 nodes (A-I)
// Returns ForkChoice and spec_name. Caller must manage mock_chain lifecycle separately.
//
// Tree structure (A-I):
//   A(0) -> B(1) -> C(2) -> D(3) -> E(4) -> F(5)
//                    \-> G(6) -> H(7) -> I(8)
fn buildTestTreeWithMockChain(allocator: Allocator, mock_chain: anytype) !struct {
    fork_choice: ForkChoice,
    spec_name: []u8,
} {
    const spec_name = try allocator.dupe(u8, "beamdev");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
        },
    };

    // Genesis block A at slot 0
    const anchor_block = createTestProtoBlock(0, 0xAA, 0x00);
    var proto_array = try ProtoArray.init(allocator, anchor_block);

    // Canonical chain with missed slots
    try proto_array.onBlock(createTestProtoBlock(1, 0xBB, 0xAA), 1); // B: slot 1
    try proto_array.onBlock(createTestProtoBlock(3, 0xCC, 0xBB), 3); // C: slot 3 (missed slot 2)
    try proto_array.onBlock(createTestProtoBlock(5, 0xDD, 0xCC), 5); // D: slot 5 (missed slot 4)
    try proto_array.onBlock(createTestProtoBlock(6, 0xEE, 0xDD), 6); // E: slot 6
    try proto_array.onBlock(createTestProtoBlock(8, 0xFF, 0xEE), 8); // F: slot 8 (missed slot 7) - HEAD

    // Fork branch from C (with its own missed slots pattern)
    try proto_array.onBlock(createTestProtoBlock(4, 0x11, 0xCC), 4); // G: slot 4, parent C
    try proto_array.onBlock(createTestProtoBlock(6, 0x22, 0x11), 6); // H: slot 6, parent G
    try proto_array.onBlock(createTestProtoBlock(7, 0x33, 0x22), 7); // I: slot 7, parent H

    const anchorCP = types.Checkpoint{ .slot = 0, .root = createTestRoot(0xAA) };
    const fc_store = ForkChoiceStore{
        .time = 8 * constants.INTERVALS_PER_SLOT,
        .timeSlots = 8,
        .latest_justified = anchorCP,
        .latest_finalized = anchorCP,
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.forkchoice);

    const fork_choice = ForkChoice{
        .allocator = allocator,
        .protoArray = proto_array,
        .anchorState = &mock_chain.genesis_state,
        .config = chain_config,
        .fcStore = fc_store,
        .attestations = std.AutoHashMap(usize, AttestationTracker).init(allocator),
        .head = createTestProtoBlock(8, 0xFF, 0xEE), // Head is F
        .safeTarget = createTestProtoBlock(8, 0xFF, 0xEE),
        .deltas = std.ArrayList(isize).init(allocator),
        .logger = module_logger,
        .gossip_signatures = SignaturesMap.init(allocator),
        .aggregated_payloads = AggregatedPayloadsMap.init(allocator),
    };

    return .{
        .fork_choice = fork_choice,
        .spec_name = spec_name,
    };
}

/// Test context that consolidates setup and cleanup for rebase tests.
/// This reduces the ~12-line defer block duplication across all tests.
const RebaseTestContext = struct {
    mock_chain: stf.MockChainData,
    fork_choice: ForkChoice,
    spec_name: []u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, num_validators: usize) !RebaseTestContext {
        var mock_chain = try stf.genMockChain(allocator, num_validators, null);
        errdefer mock_chain.deinit(allocator);
        errdefer mock_chain.genesis_state.validators.deinit();
        errdefer mock_chain.genesis_state.historical_block_hashes.deinit();
        errdefer mock_chain.genesis_state.justified_slots.deinit();
        errdefer mock_chain.genesis_state.justifications_roots.deinit();
        errdefer mock_chain.genesis_state.justifications_validators.deinit();

        var test_data = try buildTestTreeWithMockChain(allocator, &mock_chain);
        errdefer allocator.free(test_data.spec_name);
        errdefer test_data.fork_choice.protoArray.nodes.deinit();
        errdefer test_data.fork_choice.protoArray.indices.deinit();
        errdefer test_data.fork_choice.attestations.deinit();
        errdefer test_data.fork_choice.deltas.deinit();
        errdefer test_data.fork_choice.gossip_signatures.deinit();
        errdefer test_data.fork_choice.aggregated_payloads.deinit();

        return .{
            .mock_chain = mock_chain,
            .fork_choice = test_data.fork_choice,
            .spec_name = test_data.spec_name,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RebaseTestContext) void {
        // Cleanup fork_choice components
        self.fork_choice.protoArray.nodes.deinit();
        self.fork_choice.protoArray.indices.deinit();
        self.fork_choice.attestations.deinit();
        self.fork_choice.deltas.deinit();
        self.fork_choice.gossip_signatures.deinit();
        // Deinit each list in aggregated_payloads
        var it = self.fork_choice.aggregated_payloads.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |*proof| {
                proof.proof.deinit();
            }
            entry.value_ptr.deinit();
        }
        self.fork_choice.aggregated_payloads.deinit();
        self.allocator.free(self.spec_name);

        // Cleanup mock_chain genesis_state components
        self.mock_chain.genesis_state.validators.deinit();
        self.mock_chain.genesis_state.historical_block_hashes.deinit();
        self.mock_chain.genesis_state.justified_slots.deinit();
        self.mock_chain.genesis_state.justifications_roots.deinit();
        self.mock_chain.genesis_state.justifications_validators.deinit();
        self.mock_chain.deinit(self.allocator);
    }
};

test "rebase: parent pointer integrity after pruning" {
    // ========================================
    // Test: Parent pointers are correctly updated for all remaining nodes
    // ========================================
    //
    // Pre-rebase tree (A-I):
    //   A(0) -> B(1) -> C(2) -> D(3) -> E(4) -> F(5)
    //                    \-> G(6) -> H(7) -> I(8)
    //
    // Rebase to C (slot 3):
    //   - Nodes removed: A(0) slot 0 < 3, B(1) slot 1 < 3
    //   - Nodes remaining: C, D, E, F, G, H, I (entire subtree from C)
    //   - Index mapping: C:2->0, D:3->1, E:4->2, F:5->3, G:6->4, H:7->5, I:8->6
    //
    // Expected parent pointers after rebase:
    //   C(0).parent = null (new anchor)
    //   D(1).parent = 0 (C)
    //   E(2).parent = 1 (D)
    //   F(3).parent = 2 (E)
    //   G(4).parent = 0 (C) - fork branch preserved
    //   H(5).parent = 4 (G)
    //   I(6).parent = 5 (H)

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Verify pre-rebase state: 9 nodes
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 9);

    // Verify pre-rebase parent relationships
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].parent == null); // A is anchor
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].parent.? == 0); // B -> A
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].parent.? == 1); // C -> B
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[3].parent.? == 2); // D -> C
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[4].parent.? == 3); // E -> D
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[5].parent.? == 4); // F -> E
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[6].parent.? == 2); // G -> C (fork)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[7].parent.? == 6); // H -> G
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[8].parent.? == 7); // I -> H

    // Populate deltas array (required before rebase)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Rebase to C (0xCC)
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify post-rebase: 7 nodes remaining (C, D, E, F, G, H, I)
    // Entire subtree from C is preserved including fork branch
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 7);

    // Verify C is now index 0 and is the new anchor (parent = null)
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[0].blockRoot, &createTestRoot(0xCC)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].parent == null);

    // Verify D is now index 1 with parent = 0 (C)
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[1].blockRoot, &createTestRoot(0xDD)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].parent.? == 0);

    // Verify E is now index 2 with parent = 1 (D)
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[2].blockRoot, &createTestRoot(0xEE)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].parent.? == 1);

    // Verify F is now index 3 with parent = 2 (E)
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[3].blockRoot, &createTestRoot(0xFF)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[3].parent.? == 2);

    // Verify G is now index 4 with parent = 0 (C) - fork branch preserved
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[4].blockRoot, &createTestRoot(0x11)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[4].parent.? == 0);

    // Verify H is now index 5 with parent = 4 (G)
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[5].blockRoot, &createTestRoot(0x22)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[5].parent.? == 4);

    // Verify I is now index 6 with parent = 5 (H)
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[6].blockRoot, &createTestRoot(0x33)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[6].parent.? == 5);

    // Verify indices map is updated correctly
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xCC)).? == 0);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xDD)).? == 1);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xEE)).? == 2);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xFF)).? == 3);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x11)).? == 4);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x22)).? == 5);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x33)).? == 6);

    // Verify only A and B are pruned (slots < target anchor slot 3)
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xAA)) == null);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xBB)) == null);
}

test "rebase: bestChild and bestDescendant remapping" {
    // ========================================
    // Test: bestChild and bestDescendant pointers are correctly remapped
    // ========================================
    //
    // We need to establish weights first via applyDeltas to set bestChild/bestDescendant.
    // Then rebase and verify the pointers are remapped correctly.
    //
    // Setup:
    //   - 4 validators each with weight 1
    //   - All voting for F (canonical head) to establish chain as best
    //
    // Pre-rebase bestChild/bestDescendant (after applying deltas):
    //   A(0): bestChild=1(B), bestDescendant=5(F)
    //   B(1): bestChild=2(C), bestDescendant=5(F)
    //   C(2): bestChild=3(D), bestDescendant=5(F)  [D wins over G due to higher weight]
    //   D(3): bestChild=4(E), bestDescendant=5(F)
    //   E(4): bestChild=5(F), bestDescendant=5(F)
    //   F(5): bestChild=null, bestDescendant=null (leaf)
    //   G(6): bestChild=7(H), bestDescendant=8(I)  [0 weight but has children]
    //   H(7): bestChild=8(I), bestDescendant=8(I)
    //   I(8): bestChild=null, bestDescendant=null (leaf)
    //
    // After rebase to C (7 nodes remain: C, D, E, F, G, H, I):
    //   Index mapping: C:2->0, D:3->1, E:4->2, F:5->3, G:6->4, H:7->5, I:8->6
    //   C(0): bestChild=1(D), bestDescendant=3(F)
    //   D(1): bestChild=2(E), bestDescendant=3(F)
    //   E(2): bestChild=3(F), bestDescendant=3(F)
    //   F(3): bestChild=null, bestDescendant=null

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestations: All 4 validators vote for F (index 5)
    for (0..4) |validator_id| {
        const att = createTestSignedAttestation(validator_id, createTestRoot(0xFF), 8);
        try ctx.fork_choice.onGossipAttestation(att, true);
    }

    // Apply deltas to establish weights and bestChild/bestDescendant
    const deltas = try ctx.fork_choice.computeDeltas(true);
    try ctx.fork_choice.protoArray.applyDeltas(deltas, 0);

    // Verify pre-rebase bestChild/bestDescendant
    // C(2) should have bestChild=3(D) since D branch has all 4 votes
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].bestChild.? == 3); // C -> D
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].bestDescendant.? == 5); // C -> F

    // D(3) -> E(4)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[3].bestChild.? == 4);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[3].bestDescendant.? == 5);

    // E(4) -> F(5)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[4].bestChild.? == 5);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[4].bestDescendant.? == 5);

    // F(5) is leaf
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[5].bestChild == null);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[5].bestDescendant == null);

    // Note: deltas array was already populated by computeDeltas above

    // Rebase to C (0xCC)
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify 7 nodes remain (entire subtree from C preserved)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 7);

    // Verify post-rebase bestChild/bestDescendant remapping for canonical chain
    // C(0): bestChild should now be 1 (was 3), bestDescendant should be 3 (was 5)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].bestChild.? == 1);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].bestDescendant.? == 3);

    // D(1): bestChild should now be 2 (was 4), bestDescendant should be 3 (was 5)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].bestChild.? == 2);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].bestDescendant.? == 3);

    // E(2): bestChild should now be 3 (was 5), bestDescendant should be 3 (was 5)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].bestChild.? == 3);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].bestDescendant.? == 3);

    // F(3): still leaf
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[3].bestChild == null);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[3].bestDescendant == null);

    // Fork branch (G, H, I) - bestChild/bestDescendant are maintained by tree structure
    // G(4): bestChild=5(H), bestDescendant=6(I)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[4].bestChild.? == 5);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[4].bestDescendant.? == 6);

    // H(5): bestChild=6(I), bestDescendant=6(I)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[5].bestChild.? == 6);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[5].bestDescendant.? == 6);

    // I(6): leaf node
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[6].bestChild == null);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[6].bestDescendant == null);
}

test "rebase: weight preservation after rebase" {
    // ========================================
    // Test: Node weights remain unchanged after rebase
    // ========================================
    //
    // The rebase function should NOT modify weights - only remap indices.
    // Weights are set by applyDeltas, not rebase.
    //
    // Setup:
    //   - Validator 0,1,2,3: vote for F (canonical head)
    //   - Apply deltas to propagate weights up the tree
    //
    // Pre-rebase weights (bottom-up accumulation):
    //   F(5).weight = 4 (all 4 votes)
    //   E(4).weight = 4 (propagated from F)
    //   D(3).weight = 4 (propagated from E)
    //   C(2).weight = 4 (propagated from D)
    //   G(6).weight = 0 (no votes)
    //   H(7).weight = 0
    //   I(8).weight = 0
    //
    // After rebase to C (7 nodes: C, D, E, F, G, H, I):
    //   C(0).weight = 4
    //   D(1).weight = 4
    //   E(2).weight = 4
    //   F(3).weight = 4
    //   G(4).weight = 0
    //   H(5).weight = 0
    //   I(6).weight = 0

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestations: All 4 validators vote for F (index 5)
    for (0..4) |validator_id| {
        const att = createTestSignedAttestation(validator_id, createTestRoot(0xFF), 8);
        try ctx.fork_choice.onGossipAttestation(att, true);
    }

    // Apply deltas to establish weights
    const deltas = try ctx.fork_choice.computeDeltas(true);
    try ctx.fork_choice.protoArray.applyDeltas(deltas, 0);

    // Record pre-rebase weights for nodes that will remain
    const pre_rebase_weight_C = ctx.fork_choice.protoArray.nodes.items[2].weight; // C
    const pre_rebase_weight_D = ctx.fork_choice.protoArray.nodes.items[3].weight; // D
    const pre_rebase_weight_E = ctx.fork_choice.protoArray.nodes.items[4].weight; // E
    const pre_rebase_weight_F = ctx.fork_choice.protoArray.nodes.items[5].weight; // F
    const pre_rebase_weight_G = ctx.fork_choice.protoArray.nodes.items[6].weight; // G
    const pre_rebase_weight_H = ctx.fork_choice.protoArray.nodes.items[7].weight; // H
    const pre_rebase_weight_I = ctx.fork_choice.protoArray.nodes.items[8].weight; // I

    // Verify pre-rebase weights are as expected (all 4 votes propagated)
    try std.testing.expect(pre_rebase_weight_F == 4);
    try std.testing.expect(pre_rebase_weight_E == 4);
    try std.testing.expect(pre_rebase_weight_D == 4);
    try std.testing.expect(pre_rebase_weight_C == 4);

    // Verify fork branch has no weight
    try std.testing.expect(pre_rebase_weight_G == 0);
    try std.testing.expect(pre_rebase_weight_H == 0);
    try std.testing.expect(pre_rebase_weight_I == 0);

    // Note: deltas array was already populated by computeDeltas above

    // Rebase to C (0xCC)
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify 7 nodes remain
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 7);

    // Verify post-rebase weights are IDENTICAL (not recalculated)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].weight == pre_rebase_weight_C); // C
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].weight == pre_rebase_weight_D); // D
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].weight == pre_rebase_weight_E); // E
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[3].weight == pre_rebase_weight_F); // F
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[4].weight == pre_rebase_weight_G); // G
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[5].weight == pre_rebase_weight_H); // H
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[6].weight == pre_rebase_weight_I); // I

    // Verify no weight leakage - total weight unchanged for remaining subtree
    var total_weight: isize = 0;
    for (ctx.fork_choice.protoArray.nodes.items) |node| {
        total_weight += node.weight;
    }
    // Total should be 4+4+4+4+0+0+0 = 16 (same as pre-rebase for kept nodes)
    try std.testing.expect(total_weight == 16);
}

test "rebase: attestation tracker latestKnown index remapping" {
    // ========================================
    // Test: latestKnown attestation indices are correctly remapped
    // ========================================
    //
    // Setup attestations:
    //   - Validator 0: latestKnown on D (index 3) -> should remap to index 1
    //   - Validator 1: latestKnown on E (index 4) -> should remap to index 2
    //   - Validator 2: latestKnown on F (index 5) -> should remap to index 3
    //   - Validator 3: latestKnown on C (index 2) -> should remap to index 0
    //
    // All are canonical nodes, so all should be remapped (not nullified).

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestations on canonical nodes
    const att0 = createTestSignedAttestation(0, createTestRoot(0xDD), 5); // D
    try ctx.fork_choice.onGossipAttestation(att0, true);

    const att1 = createTestSignedAttestation(1, createTestRoot(0xEE), 6); // E
    try ctx.fork_choice.onGossipAttestation(att1, true);

    const att2 = createTestSignedAttestation(2, createTestRoot(0xFF), 8); // F
    try ctx.fork_choice.onGossipAttestation(att2, true);

    const att3 = createTestSignedAttestation(3, createTestRoot(0xCC), 3); // C
    try ctx.fork_choice.onGossipAttestation(att3, true);

    // Verify pre-rebase attestation indices
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 3); // D
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.index == 4); // E
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 5); // F
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown.?.index == 2); // C

    // Populate deltas array (required before rebase)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Rebase to C (0xCC)
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify post-rebase attestation indices are remapped correctly
    // D: 3 -> 1
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 1);
    // E: 4 -> 2
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.index == 2);
    // F: 5 -> 3
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 3);
    // C: 2 -> 0
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown.?.index == 0);

    // Verify slot values are preserved (not modified by rebase)
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.slot == 5);
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.slot == 6);
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.slot == 8);
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown.?.slot == 3);
}

test "rebase: attestation tracker latestNew index remapping" {
    // ========================================
    // Test: latestNew attestation indices are correctly remapped
    // ========================================
    //
    // latestNew is for gossip attestations not yet included on-chain.
    // Setup:
    //   - Validator 0: latestNew on D (index 3) -> should remap to index 1
    //   - Validator 1: latestNew on F (index 5) -> should remap to index 3

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestations as gossip (is_from_block = false)
    const att0 = createTestSignedAttestation(0, createTestRoot(0xDD), 5); // D
    try ctx.fork_choice.onGossipAttestation(att0, false); // gossip

    const att1 = createTestSignedAttestation(1, createTestRoot(0xFF), 8); // F
    try ctx.fork_choice.onGossipAttestation(att1, false); // gossip

    // Verify pre-rebase: latestNew is set, latestKnown is null
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestNew.?.index == 3);
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown == null);
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestNew.?.index == 5);
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown == null);

    // Populate deltas array (required before rebase)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Rebase to C (0xCC)
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify post-rebase latestNew indices are remapped
    // D: 3 -> 1
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestNew.?.index == 1);
    // F: 5 -> 3
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestNew.?.index == 3);
}

test "rebase: attestation tracker appliedIndex remapping" {
    // ========================================
    // Test: appliedIndex is correctly remapped after rebase
    // ========================================
    //
    // appliedIndex tracks the last applied vote index.
    // It is set when computeDeltas() is called.
    //
    // Setup:
    //   - Validator 0,1,2,3: vote for different canonical nodes
    //   - Call computeDeltas to set appliedIndex
    //   - Rebase and verify appliedIndex is remapped

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestations on canonical nodes
    const att0 = createTestSignedAttestation(0, createTestRoot(0xDD), 5); // D (index 3)
    try ctx.fork_choice.onGossipAttestation(att0, true);

    const att1 = createTestSignedAttestation(1, createTestRoot(0xEE), 6); // E (index 4)
    try ctx.fork_choice.onGossipAttestation(att1, true);

    const att2 = createTestSignedAttestation(2, createTestRoot(0xFF), 8); // F (index 5)
    try ctx.fork_choice.onGossipAttestation(att2, true);

    const att3 = createTestSignedAttestation(3, createTestRoot(0xCC), 3); // C (index 2)
    try ctx.fork_choice.onGossipAttestation(att3, true);

    // Call computeDeltas to set appliedIndex for each validator
    _ = try ctx.fork_choice.computeDeltas(true);

    // Verify pre-rebase appliedIndex values
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.appliedIndex.? == 3); // D
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.appliedIndex.? == 4); // E
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.appliedIndex.? == 5); // F
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.appliedIndex.? == 2); // C

    // Rebase to C (0xCC)
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify post-rebase appliedIndex remapping
    // D: 3 -> 1
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.appliedIndex.? == 1);
    // E: 4 -> 2
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.appliedIndex.? == 2);
    // F: 5 -> 3
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.appliedIndex.? == 3);
    // C: 2 -> 0
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.appliedIndex.? == 0);
}

test "rebase: orphaned attestations set to null" {
    // ========================================
    // Test: Attestations pointing to pruned (ancestor) nodes are nullified
    // ========================================
    //
    // Key insight: Rebase preserves the ENTIRE subtree from target anchor.
    // G, H, I are descendants of C, so they're NOT pruned!
    // Only A (slot 0) and B (slot 1) are pruned because their slots < target slot (3).
    //
    // Note: We avoid voting on A (genesis, slot 0) because attestations with
    // head == target == source at slot 0 may be invalid. We use B for both
    // orphaned attestation tests.
    //
    // Setup:
    //   - Validator 0: latestKnown on B (index 1, slot 1) -> should become null (pruned)
    //   - Validator 1: latestKnown on B (index 1, slot 1) -> should become null (pruned)
    //   - Validator 2: latestKnown on G (index 6, slot 4) -> should remap to 4 (preserved)
    //   - Validator 3: latestKnown on D (index 3, slot 5) -> should remap to 1 (preserved)

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestations on ancestor nodes (will be pruned due to slot < target slot)
    // Both validators 0 and 1 vote on B (slot 1) which will be pruned
    const att0 = createTestSignedAttestation(0, createTestRoot(0xBB), 1); // B (slot 1)
    try ctx.fork_choice.onGossipAttestation(att0, true);

    const att1 = createTestSignedAttestation(1, createTestRoot(0xBB), 1); // B (slot 1)
    try ctx.fork_choice.onGossipAttestation(att1, true);

    // Setup attestations on descendant nodes (will be preserved)
    const att2 = createTestSignedAttestation(2, createTestRoot(0x11), 4); // G (slot 4, fork)
    try ctx.fork_choice.onGossipAttestation(att2, true);

    const att3 = createTestSignedAttestation(3, createTestRoot(0xDD), 5); // D (slot 5)
    try ctx.fork_choice.onGossipAttestation(att3, true);

    // Call computeDeltas to set appliedIndex
    _ = try ctx.fork_choice.computeDeltas(true);

    // Verify pre-rebase attestation indices
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 1); // B
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.appliedIndex.? == 1);
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.index == 1); // B
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 6); // G
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown.?.index == 3); // D

    // Rebase to C (0xCC) - removes A and B (slots < 3), keeps all descendants including G, H, I
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify 7 nodes remain
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 7);

    // Verify orphaned attestations (on pruned ancestors) are nullified
    // Validator 0: B was pruned -> latestKnown = null, appliedIndex = null
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown == null);
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.appliedIndex == null);

    // Validator 1: B was pruned -> latestKnown = null, appliedIndex = null
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown == null);
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.appliedIndex == null);

    // Validator 2: G is preserved -> remapped from 6 to 4
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 4);
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.appliedIndex.? == 4);

    // Validator 3: D is preserved -> remapped from 3 to 1
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown.?.index == 1);
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.appliedIndex.? == 1);
}

test "rebase: mixed latestKnown and latestNew with orphaned votes" {
    // ========================================
    // Test: Complex scenario with both latestKnown and latestNew
    // ========================================
    //
    // Key insight: G, H, I are descendants of C and are NOT pruned.
    // Only A (slot 0) and B (slot 1) are pruned because their slots < target slot (3).
    //
    // Note: We avoid voting on A (genesis, slot 0) because attestations with
    // head == target == source at slot 0 may be invalid. We use B instead.
    //
    // Setup:
    //   - Validator 0: latestKnown on D (preserved), latestNew on E (preserved)
    //   - Validator 1: latestKnown on B (pruned), latestNew on F (preserved)
    //   - Validator 2: latestKnown on G (preserved fork), latestNew on I (preserved fork)
    //
    // After rebase to C (7 nodes: C, D, E, F, G, H, I):
    //   Index mapping: C:2->0, D:3->1, E:4->2, F:5->3, G:6->4, H:7->5, I:8->6
    //   - Validator 0: latestKnown remapped (D:3->1), latestNew remapped (E:4->2)
    //   - Validator 1: latestKnown nullified (B pruned), latestNew remapped (F:5->3)
    //   - Validator 2: latestKnown remapped (G:6->4), latestNew remapped (I:8->6)

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Validator 0: latestKnown on D (slot 5), then latestNew on E (slot 6 > 5)
    const att0_known = createTestSignedAttestation(0, createTestRoot(0xDD), 5); // D
    try ctx.fork_choice.onGossipAttestation(att0_known, true);
    const att0_new = createTestSignedAttestation(0, createTestRoot(0xEE), 6); // E
    try ctx.fork_choice.onGossipAttestation(att0_new, false);

    // Validator 1: latestKnown on B (slot 1, will be pruned), latestNew on F (slot 8 > 1)
    const att1_known = createTestSignedAttestation(1, createTestRoot(0xBB), 1); // B
    try ctx.fork_choice.onGossipAttestation(att1_known, true);
    const att1_new = createTestSignedAttestation(1, createTestRoot(0xFF), 8); // F
    try ctx.fork_choice.onGossipAttestation(att1_new, false);

    // Validator 2: latestKnown on G (slot 4, preserved), latestNew on I (slot 7 > 4, preserved)
    const att2_known = createTestSignedAttestation(2, createTestRoot(0x11), 4); // G
    try ctx.fork_choice.onGossipAttestation(att2_known, true);
    const att2_new = createTestSignedAttestation(2, createTestRoot(0x33), 7); // I
    try ctx.fork_choice.onGossipAttestation(att2_new, false);

    // Verify pre-rebase state
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 3); // D
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestNew.?.index == 4); // E
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.index == 1); // B
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestNew.?.index == 5); // F
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 6); // G
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestNew.?.index == 8); // I

    // Populate deltas array (required before rebase)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Rebase to C (0xCC)
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify 7 nodes remain
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 7);

    // Validator 0: both preserved, both remapped
    // D: 3 -> 1, E: 4 -> 2
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 1);
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestNew.?.index == 2);

    // Validator 1: latestKnown (B) nullified (pruned), latestNew (F) remapped
    // B: pruned -> null, F: 5 -> 3
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown == null);
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestNew.?.index == 3);

    // Validator 2: both preserved (fork branch kept), both remapped
    // G: 6 -> 4, I: 8 -> 6
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 4);
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestNew.?.index == 6);
}

test "rebase: edge case - genesis rebase (no-op)" {
    // ========================================
    // Test: Rebasing to genesis anchor is effectively a no-op
    // ========================================
    //
    // When rebasing to the current anchor (genesis), no nodes should be removed.
    // All attestations should remain unchanged (indices stay the same).

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestation on F
    const att = createTestSignedAttestation(0, createTestRoot(0xFF), 8);
    try ctx.fork_choice.onGossipAttestation(att, true);

    // Record pre-rebase state
    const pre_node_count = ctx.fork_choice.protoArray.nodes.items.len;
    const pre_att_index = ctx.fork_choice.attestations.get(0).?.latestKnown.?.index;

    // Verify we have all 9 nodes
    try std.testing.expect(pre_node_count == 9);
    try std.testing.expect(pre_att_index == 5); // F

    // Populate deltas array (required before rebase)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Rebase to A (genesis, 0xAA) - should be a no-op since A is already anchor
    try ctx.fork_choice.rebase(createTestRoot(0xAA), null);

    // Verify no nodes were removed
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 9);

    // Verify A is still at index 0 with null parent
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[0].blockRoot, &createTestRoot(0xAA)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].parent == null);

    // Verify attestation index unchanged
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 5);

    // Verify all other nodes still have correct parents
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].parent.? == 0); // B -> A
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].parent.? == 1); // C -> B
}

test "rebase: edge case - rebase to head (prune all but head)" {
    // ========================================
    // Test: Rebasing to current head removes all ancestors
    // ========================================
    //
    // Rebase to F (head) should leave only F as the anchor.
    // All other nodes (A, B, C, D, E, G, H, I) are pruned.

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestation on F
    const att = createTestSignedAttestation(0, createTestRoot(0xFF), 8);
    try ctx.fork_choice.onGossipAttestation(att, true);

    // Populate deltas array (required before rebase)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Rebase to F (0xFF, head)
    try ctx.fork_choice.rebase(createTestRoot(0xFF), null);

    // Verify only F remains
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 1);

    // Verify F is now at index 0 with null parent
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[0].blockRoot, &createTestRoot(0xFF)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].parent == null);

    // F should have no children, so bestChild and bestDescendant should be null
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].bestChild == null);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].bestDescendant == null);

    // Attestation on F: 5 -> 0
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 0);

    // Verify all other roots are removed from indices
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xAA)) == null);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xBB)) == null);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xCC)) == null);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xDD)) == null);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xEE)) == null);
}

test "rebase: edge case - missed slots preserved in remaining tree" {
    // ========================================
    // Test: Missed slots don't affect index mapping
    // ========================================
    //
    // The test tree has missed slots (2, 4, 7).
    // Index mapping should be based on array position, not slot numbers.
    //
    // After rebase to D (slot 5):
    //   - getCanonicalView adds A, B, C, D (ancestors) plus all descendants
    //   - This includes G, H, I (siblings/descendants of C)
    //   - Slot filter removes: A (0), B (1), C (3), G (4) as slot < 5
    //   - Remaining: D (slot 5), E (slot 6), F (slot 8), H (slot 6), I (slot 7)
    //
    // Note: H and I are kept but G (their ancestor) is removed, making H orphaned.
    // H's parent becomes null (orphan) because G was removed.
    //
    // Indices: D=0, E=1, F=2, H=3, I=4

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Populate deltas array (required before rebase)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Rebase to D (0xDD, slot 5)
    try ctx.fork_choice.rebase(createTestRoot(0xDD), null);

    // Verify 5 nodes remain: D, E, F
    // (G is removed due to slot 4 < 5 as well as H and I)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 3);

    // Verify canonical chain slots
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].slot == 5); // D
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].slot == 6); // E
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].slot == 8); // F

    // Verify contiguous indices
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xDD)).? == 0);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xEE)).? == 1);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xFF)).? == 2);
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x22)) == null); // H
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x33)) == null); // I

    // Verify parent chain for canonical branch
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].parent == null); // D is anchor
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].parent.? == 0); // E -> D
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].parent.? == 1); // F -> E
}

test "rebase: error - InvalidTargetAnchor for non-existent root" {
    // ========================================
    // Test: Rebasing to non-existent root returns error
    // ========================================

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Record pre-rebase state
    const pre_node_count = ctx.fork_choice.protoArray.nodes.items.len;

    // Populate deltas array (required before rebase in normal cases)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Try to rebase to non-existent root
    const non_existent_root = createTestRoot(0x99);
    const result = ctx.fork_choice.rebase(non_existent_root, null);

    // Verify error is returned
    try std.testing.expectError(ForkChoiceError.InvalidTargetAnchor, result);

    // Verify tree is unchanged (rebase failed before modifying state)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == pre_node_count);
}

test "rebase: complex fork with attestations on multiple branches" {
    // ========================================
    // Test: Rebasing with attestations on fork branches
    // ========================================
    //
    // Tree:
    //   A -> B -> C -> D -> E -> F (canonical)
    //             \-> G -> H -> I (fork)
    //
    // Rebase to D (slot 5):
    //   - getCanonicalView includes: A, B, C, D, E, F, G, H, I (all descendants of path to D)
    //   - Slot filter removes: A (0), B (1), C (3), G (4) - all have slot < 5
    //   - Remaining: D (5), E (6), F (8), H (6), I (7) = 5 nodes
    //   - H becomes orphaned (parent G was removed) but is kept due to slot >= 5
    //
    // Index mapping: D:3->0, E:4->1, F:5->2, H:7->3, I:8->4

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestations on various nodes
    // Canonical: validators 0, 1 on E and F
    const att0 = createTestSignedAttestation(0, createTestRoot(0xEE), 6); // E
    try ctx.fork_choice.onGossipAttestation(att0, true);
    const att1 = createTestSignedAttestation(1, createTestRoot(0xFF), 8); // F
    try ctx.fork_choice.onGossipAttestation(att1, true);

    // Fork: validators 2, 3 on H and I (these are kept despite fork, slot >= 5)
    const att2 = createTestSignedAttestation(2, createTestRoot(0x22), 6); // H
    try ctx.fork_choice.onGossipAttestation(att2, true);
    const att3 = createTestSignedAttestation(3, createTestRoot(0x33), 7); // I
    try ctx.fork_choice.onGossipAttestation(att3, true);

    // Populate deltas array (required before rebase)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Rebase to D (0xDD)
    try ctx.fork_choice.rebase(createTestRoot(0xDD), null);

    // Verify 5 nodes remain: D, E, F,
    // (G is removed due to slot 4 < 5 as well as H and I)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 3);

    // Verify canonical attestations are remapped
    // E: was 4, now 1
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 1);
    // F: was 5, now 2
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.index == 2);

    // Verify fork attestations are ALSO removed
    // H
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown == null);
    // I
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown == null);

    // Verify G, H and I removed
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x11)) == null); // G removed
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x22)) == null); // H
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x33)) == null); // I
}

test "rebase: heavy attestation load - all validators tracked correctly" {
    // ========================================
    // Test: Large number of attestations are all correctly updated
    // ========================================
    //
    // This test verifies that with many validators, all attestation trackers
    // are correctly updated during rebase.

    const allocator = std.testing.allocator;

    // Create a mock chain with more validators
    var mock_chain = try stf.genMockChain(allocator, 32, null);
    defer mock_chain.deinit(allocator);
    defer mock_chain.genesis_state.validators.deinit();
    defer mock_chain.genesis_state.historical_block_hashes.deinit();
    defer mock_chain.genesis_state.justified_slots.deinit();
    defer mock_chain.genesis_state.justifications_roots.deinit();
    defer mock_chain.genesis_state.justifications_validators.deinit();

    const spec_name = try allocator.dupe(u8, "beamdev");
    defer allocator.free(spec_name);
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
        },
    };

    // Build smaller tree: A -> B -> C -> D
    const anchor_block = createTestProtoBlock(0, 0xAA, 0x00);
    var proto_array = try ProtoArray.init(allocator, anchor_block);
    defer proto_array.nodes.deinit();
    defer proto_array.indices.deinit();

    try proto_array.onBlock(createTestProtoBlock(1, 0xBB, 0xAA), 1);
    try proto_array.onBlock(createTestProtoBlock(2, 0xCC, 0xBB), 2);
    try proto_array.onBlock(createTestProtoBlock(3, 0xDD, 0xCC), 3);

    const anchorCP = types.Checkpoint{ .slot = 0, .root = createTestRoot(0xAA) };
    const fc_store = ForkChoiceStore{
        .time = 3 * constants.INTERVALS_PER_SLOT,
        .timeSlots = 3,
        .latest_justified = anchorCP,
        .latest_finalized = anchorCP,
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.forkchoice);

    var fork_choice = ForkChoice{
        .allocator = allocator,
        .protoArray = proto_array,
        .anchorState = &mock_chain.genesis_state,
        .config = chain_config,
        .fcStore = fc_store,
        .attestations = std.AutoHashMap(usize, AttestationTracker).init(allocator),
        .head = createTestProtoBlock(3, 0xDD, 0xCC),
        .safeTarget = createTestProtoBlock(3, 0xDD, 0xCC),
        .deltas = std.ArrayList(isize).init(allocator),
        .logger = module_logger,
        .gossip_signatures = SignaturesMap.init(allocator),
        .aggregated_payloads = AggregatedPayloadsMap.init(allocator),
    };
    // Note: We don't defer proto_array.nodes/indices.deinit() here because they're
    // moved into fork_choice and will be deinitialized separately
    defer fork_choice.attestations.deinit();
    defer fork_choice.deltas.deinit();
    defer fork_choice.gossip_signatures.deinit();
    defer fork_choice.aggregated_payloads.deinit();

    // Setup attestations for all 32 validators
    // Distribute across C and D
    for (0..32) |validator_id| {
        const target = if (validator_id % 2 == 0) createTestRoot(0xCC) else createTestRoot(0xDD);
        const slot: types.Slot = if (validator_id % 2 == 0) 2 else 3;
        const att = createTestSignedAttestation(validator_id, target, slot);
        try fork_choice.onGossipAttestation(att, true);
    }

    // Verify all 32 attestations are set
    for (0..32) |validator_id| {
        const tracker = fork_choice.attestations.get(validator_id);
        try std.testing.expect(tracker != null);
        try std.testing.expect(tracker.?.latestKnown != null);
    }

    // Populate deltas array (required before rebase)
    _ = try fork_choice.computeDeltas(true);

    // Rebase to C (0xCC)
    try fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify 2 nodes remain: C, D
    try std.testing.expect(fork_choice.protoArray.nodes.items.len == 2);

    // Verify all attestations are correctly updated
    for (0..32) |validator_id| {
        const tracker = fork_choice.attestations.get(validator_id).?;
        try std.testing.expect(tracker.latestKnown != null);

        if (validator_id % 2 == 0) {
            // Was on C (index 2), now index 0
            try std.testing.expect(tracker.latestKnown.?.index == 0);
        } else {
            // Was on D (index 3), now index 1
            try std.testing.expect(tracker.latestKnown.?.index == 1);
        }
    }
}

test "rebase: deltas array is properly shrunk" {
    // ========================================
    // Test: Verify deltas array is updated during rebase
    // ========================================
    //
    // The deltas array is used for vote tracking and should be
    // properly managed during rebase (swapRemove is used).
    //
    // Key insight: Rebase preserves entire subtree from target anchor.
    // When rebasing to C (slot 3), only A and B are removed (slots < 3).
    // G, H, I are descendants of C and are preserved.
    //
    // Pre-rebase: 9 nodes (A, B, C, D, E, F, G, H, I)
    // Post-rebase: 7 nodes (C, D, E, F, G, H, I)

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestations to populate deltas
    for (0..4) |validator_id| {
        const att = createTestSignedAttestation(validator_id, createTestRoot(0xFF), 8);
        try ctx.fork_choice.onGossipAttestation(att, true);
    }

    // Compute deltas to populate the deltas array
    _ = try ctx.fork_choice.computeDeltas(true);

    // Record pre-rebase deltas length (should match node count = 9)
    const pre_deltas_len = ctx.fork_choice.deltas.items.len;
    try std.testing.expect(pre_deltas_len == 9);

    // Rebase to C (0xCC) - removes 2 nodes (A, B with slots < 3)
    // G, H, I are preserved as descendants of C
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify nodes reduced to 7 (C, D, E, F, G, H, I)
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 7);

    // Deltas array uses swapRemove, so length should also be reduced
    // The deltas array should have 7 elements now
    try std.testing.expect(ctx.fork_choice.deltas.items.len == 7);
}

test "rebase: to fork branch node (G) removes previous canonical chain" {
    // ========================================
    // Test: Rebasing to a fork branch node
    // ========================================
    //
    // This tests a scenario NOT covered by other tests: rebasing to a fork
    // branch node instead of a canonical chain node.
    //
    // Pre-rebase tree:
    //   Slot:  0      1      3      5      6      8
    //         [A] -> [B] -> [C] -> [D] -> [E] -> [F]    <- Previous canonical chain
    //                        \
    //                         [G] -> [H] -> [I]         <- Fork branch (becomes new canonical)
    //                        (s4)   (s6)   (s7)
    //
    //   Indices: A=0, B=1, C=2, D=3, E=4, F=5, G=6, H=7, I=8
    //
    // How getCanonicalView works:
    //   1. First loop: walks from G UP via parents -> adds A, B, C, G
    //   2. Second loop: walks from index 7+ -> adds H, I (descendants of G)
    //   Note: D, E, F are at indices 3, 4, 5 (before G's index 6)
    //         so they're NOT included in canonical view!
    //
    // Rebase to G (slot 4):
    //   - Canonical view = {A, B, C, G, H, I}
    //   - D, E, F are NOT in canonical view -> removed entirely
    //   - Slot filter removes: A (0), B (1), C (3) as slot < 4
    //   - Remaining: G (4), H (6), I (7) = 3 nodes
    //
    // Post-rebase tree:
    //   [G] -> [H] -> [I]    <- Only the fork branch remains
    //
    // Key insight: Rebasing to a fork node means the fork becomes the new
    // canonical chain, and the previous canonical chain is discarded entirely.
    //
    // Index mapping: G:6->0, H:7->1, I:8->2

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Setup attestations to test remapping and orphaning
    // Attestations on previous canonical chain (will become null after rebase)
    const att0 = createTestSignedAttestation(0, createTestRoot(0xDD), 5); // D
    try ctx.fork_choice.onGossipAttestation(att0, true);
    const att1 = createTestSignedAttestation(1, createTestRoot(0xFF), 8); // F
    try ctx.fork_choice.onGossipAttestation(att1, true);

    // Attestations on fork branch (will be remapped)
    const att2 = createTestSignedAttestation(2, createTestRoot(0x22), 6); // H
    try ctx.fork_choice.onGossipAttestation(att2, true);
    const att3 = createTestSignedAttestation(3, createTestRoot(0x33), 7); // I
    try ctx.fork_choice.onGossipAttestation(att3, true);

    // Verify pre-rebase state
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 9);
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 3); // D
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.index == 5); // F
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 7); // H
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown.?.index == 8); // I

    // Populate deltas array (required before rebase)
    _ = try ctx.fork_choice.computeDeltas(true);

    // Rebase to G (0x11) - the fork branch node
    try ctx.fork_choice.rebase(createTestRoot(0x11), null);

    // Verify only 3 nodes remain: G, H, I
    // D, E, F were NOT in canonical view and are removed entirely
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 3);

    // Verify G is now the anchor at index 0
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[0].blockRoot, &createTestRoot(0x11)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].slot == 4);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[0].parent == null); // G is new anchor

    // Verify H -> G (index 1, parent = 0)
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[1].blockRoot, &createTestRoot(0x22)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].slot == 6);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[1].parent.? == 0); // H -> G

    // Verify I -> H (index 2, parent = 1)
    try std.testing.expect(std.mem.eql(u8, &ctx.fork_choice.protoArray.nodes.items[2].blockRoot, &createTestRoot(0x33)));
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].slot == 7);
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items[2].parent.? == 1); // I -> H

    // Verify indices map is updated correctly
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x11)).? == 0); // G
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x22)).? == 1); // H
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0x33)).? == 2); // I

    // Verify all removed nodes are gone from indices
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xAA)) == null); // A removed
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xBB)) == null); // B removed
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xCC)) == null); // C removed
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xDD)) == null); // D removed (not in canonical view)
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xEE)) == null); // E removed (not in canonical view)
    try std.testing.expect(ctx.fork_choice.protoArray.indices.get(createTestRoot(0xFF)) == null); // F removed (not in canonical view)

    // Verify attestations on removed nodes (D, F) are nullified
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown == null); // D was removed
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown == null); // F was removed

    // Verify attestations on fork branch are remapped correctly
    // H: 7 -> 1
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 1);
    // I: 8 -> 2
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown.?.index == 2);
}
