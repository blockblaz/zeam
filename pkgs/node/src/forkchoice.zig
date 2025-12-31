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
    // we can construct proto attestations from the anchor state justifications but will not exactly know
    // the attestations
    attestation: ?types.SignedAttestation = null,
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
        };
        _ = try fc.updateHead();
        return fc;
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
            const parent_node = self.protoArray.nodes.items[current_node.parent orelse return ForkChoiceError.InvalidCanonicalTraversal];
            if (canonical_view.contains(parent_node.blockRoot)) {
                try canonical_view.put(current_node.blockRoot, {});
            }
            current_idx += 1;
        }
    }

    /// Get all ancestor block roots from the current finalized block,
    /// traversing backwards, and collecting all blocks with slot > previousFinalizedSlot.
    /// Stops traversal when previousFinalizedSlot is reached or at genesis.
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

    pub fn rebase(self: *Self, targetAnchorRoot: types.Root, canonicalViewOrNull: ?*std.AutoHashMap(types.Root, void)) !void {
        const target_anchor_idx = self.protoArray.indices.get(targetAnchorRoot) orelse return ForkChoiceError.InvalidTargetAnchor;
        const target_anchor_slot = self.protoArray.nodes.items[target_anchor_idx].slot;

        var canonical_view = canonicalViewOrNull orelse blk: {
            var local_view = std.AutoHashMap(types.Root, void).init(self.allocator);
            try self.getCanonicalView(&local_view, targetAnchorRoot, null);
            break :blk &local_view;
        };

        // prune, intetesting thing to note is the entire subtree of targetAnchorRoot is not affected and is to be
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
                // because after removal next node would be refered at the same current idx
                _ = self.protoArray.nodes.orderedRemove(current_idx);
                // don't need order preserving on deltas as they are always set to zero before their use
                _ = self.deltas.swapRemove(current_idx);
                _ = self.protoArray.indices.remove(current_node.blockRoot);
                shifted_left += 1;
            }
        }

        // correct parent, bestchild and best decendant indices using the created old to new map
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

            // fix bestchild and descendant
            if (current_node.bestChild) |old_best_child_idx| {
                // we should be able to lookup new index otherwise its an irrecoverable error
                const new_best_child_idx = old_indices_to_new.get(old_best_child_idx) orelse @panic("invalid old index lookup for rebased best child");
                current_node.bestChild = new_best_child_idx;

                // best descendant should always be there when there is a best child
                const old_best_descendant_idx = current_node.bestDescendant orelse @panic("invalid forkchoice with null best descendant for a non null best child");
                // we should be able to lookup new index otherwise its an irrecoverable error
                const new_best_descendant_idx = old_indices_to_new.get(old_best_descendant_idx) orelse @panic("invalid old index loopkup for rebase best descendant");
                current_node.bestDescendant = new_best_descendant_idx;
            } else {
                // confirm best descandant is also null
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
                // this simple assignmet suffices both for cases where new index is found i.e. is canonical
                // or not, in which case it needs to point to null
                entry.value_ptr.appliedIndex = new_index_lookup;
            }

            // fix latestknown
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

    pub fn getCanonicalAncestorAtDepth(self: *Self, min_depth: usize) !ProtoBlock {
        var depth = min_depth;
        var current_idx = self.protoArray.indices.get(self.head.blockRoot) orelse return ForkChoiceError.InvalidHeadIndex;
        if (current_idx < depth) {
            current_idx = 0;
            depth = 0;
        }

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

    pub fn getProposalAttestations(self: *Self) ![]types.SignedAttestation {
        var included_attestations = std.ArrayList(types.SignedAttestation).init(self.allocator);
        const latest_justified = self.fcStore.latest_justified;

        // TODO naive strategy to include all attestations that are consistent with the latest justified
        // replace by the other mini 3sf simple strategy to loop and see if justification happens and
        // till no further attestations can be added
        for (0..self.config.genesis.numValidators()) |validator_id| {
            const validator_attestation = ((self.attestations.get(validator_id) orelse AttestationTracker{})
                //
                .latestKnown orelse ProtoAttestation{}).attestation;

            if (validator_attestation) |signed_attestation| {
                if (std.mem.eql(u8, &latest_justified.root, &signed_attestation.message.data.source.root)) {
                    try included_attestations.append(signed_attestation);
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
        self.head = try self.computeFCHead(true, 0);
        // Update the lean_head_slot metric
        zeam_metrics.metrics.lean_head_slot.set(self.head.slot);
        return self.head;
    }

    pub fn updateSafeTarget(self: *Self) !ProtoBlock {
        const cutoff_weight = try std.math.divCeil(u64, 2 * self.config.genesis.numValidators(), 3);
        self.safeTarget = try self.computeFCHead(false, cutoff_weight);
        return self.safeTarget;
    }

    pub fn onAttestation(self: *Self, signed_attestation: types.SignedAttestation, is_from_block: bool) !void {
        // Attestation validation is done by the caller (chain layer)
        // This function assumes the attestation has already been validated

        // attestation has to be of an ancestor of the current slot
        const attestation = signed_attestation.message;
        const validator_id = attestation.validator_id;
        const attestation_slot = attestation.data.slot;

        // This get should never fail after validation, but we keep the check for safety
        const new_head_index = self.protoArray.indices.get(attestation.data.head.root) orelse {
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
                    .attestation = signed_attestation,
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
                    .attestation = signed_attestation,
                };
            }
        }
        try self.attestations.put(validator_id, attestation_tracker);
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

const ForkChoiceError = error{
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
