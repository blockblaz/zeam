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
const keymanager = @import("@zeam/key-manager");
const ThreadPool = @import("@zeam/thread-pool").ThreadPool;

const constants = @import("./constants.zig");

const Root = types.Root;
const ValidatorIndex = types.ValidatorIndex;
const ZERO_SIGBYTES = types.ZERO_SIGBYTES;

/// Re-exported from @zeam/params so the import gate and the signature verifier share one value.
pub const MAX_ATTESTATIONS_DATA: usize = params.MAX_ATTESTATIONS_DATA;

fn validateAttestationDataLimits(
    allocator: Allocator,
    aggregated_attestations: []const types.AggregatedAttestation,
) ForkChoiceError!void {
    var seen = std.AutoHashMap(types.AttestationData, void).init(allocator);
    defer seen.deinit();
    for (aggregated_attestations) |agg_att| {
        const gop = seen.getOrPut(agg_att.data) catch return ForkChoiceError.InvalidForkchoiceBlock;
        if (gop.found_existing) return ForkChoiceError.DuplicateAttestationData;
    }
    if (seen.count() > MAX_ATTESTATIONS_DATA) return ForkChoiceError.TooManyAttestationData;
}

const ProtoBlock = types.ProtoBlock;
pub const ProtoNode = struct {
    // Fields from ProtoBlock
    slot: types.Slot,
    proposer_index: types.ValidatorIndex,
    blockRoot: Root,
    parentRoot: Root,
    stateRoot: Root,
    timeliness: bool,
    confirmed: bool,
    // Fields from ProtoMeta
    parent: ?usize,
    weight: isize,
    bestChild: ?usize,
    bestDescendant: ?usize,
    depth: usize, // depth from the anchor/forkchoice root

    // idx of next sibling, for easy traversal of children 0 means no there is no next sibling as 0 is anchor root and isn't anyone's sibling
    nextSibling: usize,
    // idx of the first and latest added children for easy children traversal through siblings
    firstChild: usize,
    latestChild: usize,
    numChildren: usize,

    // info populated lazily for tree visualization in snapshot for efficiency purposes
    numBranches: ?usize = null,

    pub fn format(self: ProtoNode, writer: anytype) !void {
        try writer.print("ProtoNode{{ slot={d}, weight={d}, blockRoot=0x{x} }}", .{
            self.slot,
            self.weight,
            &self.blockRoot,
        });
    }
};

pub const ProtoArray = struct {
    nodes: std.ArrayList(ProtoNode),
    indices: std.AutoHashMap(types.Root, usize),
    allocator: Allocator,

    const Self = @This();
    pub fn init(allocator: Allocator, anchorBlock: ProtoBlock) !Self {
        var proto_array = Self{
            .nodes = .empty,
            .indices = std.AutoHashMap(types.Root, usize).init(allocator),
            .allocator = allocator,
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
        // index at which node will be inserted
        const node_index = self.nodes.items.len;
        const parent = self.indices.get(block.parentRoot);

        // some tree book keeping
        var depth: usize = 0;
        if (parent) |parent_id| {
            depth = self.nodes.items[parent_id].depth + 1;

            // update next sibling of the current parent's latest
            const prevLatestChild = self.nodes.items[parent_id].latestChild;
            if (prevLatestChild == 0) {
                self.nodes.items[parent_id].firstChild = node_index;
            } else {
                self.nodes.items[prevLatestChild].nextSibling = node_index;
            }
            self.nodes.items[parent_id].latestChild = node_index;
            self.nodes.items[parent_id].numChildren += 1;
        }

        // TODO extend is not working so copy data for now
        // const node = utils.Extend(ProtoNode, block, .{
        //     .parent = parent,
        //     .weight = weight,
        //     // bestChild and bestDescendant are left null
        // });
        const node = ProtoNode{
            .slot = block.slot,
            .proposer_index = block.proposer_index,
            .blockRoot = block.blockRoot,
            .parentRoot = block.parentRoot,
            .stateRoot = block.stateRoot,
            .timeliness = block.timeliness,
            .confirmed = block.confirmed,
            .parent = parent,
            .weight = 0,
            .bestChild = null,
            .bestDescendant = null,

            // tree book keeping
            .depth = depth,
            .nextSibling = 0,
            .firstChild = 0,
            .latestChild = 0,
            .numChildren = 0,
        };
        try self.nodes.append(self.allocator, node);
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

    // Internal unlocked version - assumes caller holds lock
    fn applyDeltasUnlocked(self: *Self, deltas: []isize, cutoff_weight: u64) !void {
        if (deltas.len != self.nodes.items.len) {
            return ForkChoiceError.InvalidDeltas;
        }

        // iterate backwards apply deltas and propagating deltas to parents
        var node_idx_a = self.nodes.items.len;
        while (node_idx_a > 0) {
            node_idx_a -= 1;
            const node_idx = node_idx_a;
            const node_delta = deltas[node_idx];
            self.nodes.items[node_idx].weight += node_delta;
            if (self.nodes.items[node_idx].parent) |parent_idx| {
                deltas[parent_idx] += node_delta;
            }
        }

        // re-iterate backwards and calc best child and descendant
        // there seems to be no filter block tree in the mini3sf fc
        var node_idx_b = self.nodes.items.len;
        while (node_idx_b > 0) {
            node_idx_b -= 1;
            const node_idx = node_idx_b;
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
                        } else if (bestChild.weight == node.weight and (std.mem.order(u8, &bestChild.blockRoot, &node.blockRoot) == .lt)) {
                            // tie break by lexicographically larger block root (leanSpec-compatible)
                            updateBest = true;
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
    // Shared slot/interval clock - updated by the forkchoice on every tick.
    // Also pointed to by ZeamLoggerConfig so loggers can annotate each line
    // with the current slot and interval without acquiring any lock.
    slot_clock: zeam_utils.SlotTimeClock,

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
    // we store AttestationData here since signatures are stored separately in attestation_signatures/latest_*_aggregated_payloads
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
    thread_pool: *ThreadPool,
    /// Minimum (children + gossip-sig) inputs the aggregator pre-filter
    /// requires before letting an `att_data` reach
    /// `computeAggregatedSignatures`. Threaded through from the
    /// `--min-aggregation-inputs` CLI flag and consumed by
    /// `pruneTrivialFromAggregateSnapshot` (NOT by the FFI). See
    /// `isAggregatorTrivialInput` for the predicate semantics.
    min_aggregation_inputs: u32 = types.default_min_aggregation_inputs,
};

// Use shared signature map types from types package
const StoredSignature = types.StoredSignature;
const SignaturesMap = types.SignaturesMap;
const StoredAggregatedPayload = types.StoredAggregatedPayload;
const AggregatedPayloadsList = types.AggregatedPayloadsList;
const AggregatedPayloadsMap = types.AggregatedPayloadsMap;

/// Tracks whether the forkchoice has observed a real justified checkpoint via onBlock.
/// For genesis (anchor slot == 0) we start ready; for checkpoint-sync or DB restore we
/// start initing and transition once the first block-driven justified update arrives.
pub const ForkChoiceStatus = enum { initing, ready };

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
    // Thread-safe access protection
    mutex: zeam_utils.SyncRwLock,
    // Per-validator XMSS signatures learned from gossip, keyed by (AttestationData, ValidatorIndex).
    attestation_signatures: SignaturesMap,
    // Aggregated signature proofs pending processing.
    // These payloads are "new" and migrate to known payloads via interval ticks.
    latest_new_aggregated_payloads: AggregatedPayloadsMap,
    // Aggregated signature proofs that are known and contribute to fork choice weights.
    // Used for recursive signature aggregation when building blocks.
    latest_known_aggregated_payloads: AggregatedPayloadsMap,
    // Aggregated signature proofs observed in the most recently processed block slot.
    // This is observability-only; fork choice uses latest_known_aggregated_payloads.
    latest_block_aggregated_payloads: AggregatedPayloadsMap,
    latest_block_aggregated_payloads_slot: ?types.Slot,
    /// Coverage of latest_new_aggregated_payloads captured just before the last
    /// acceptNewAttestationsUnlocked merge.  Used to report "prev_new" in printSlot.
    saved_pre_merge_new_coverage: ?SavedPreMergeCoverage = null,
    // Mutex to protect concurrent access to signature/payload maps
    signatures_mutex: zeam_utils.SyncMutex,
    // Tracks whether FC has observed a real justified checkpoint via block processing.
    // Starts as `initing` for checkpoint-sync init (anchor slot > 0); transitions to
    // `ready` on the first block-driven justified update.  Validator duties (block
    // production, attestation) must not run while status == .initing.
    status: ForkChoiceStatus,
    // Shared worker pool used for CPU-heavy attestation compaction.
    thread_pool: *ThreadPool,
    /// Threshold consumed by `pruneTrivialFromAggregateSnapshot` on
    /// every `aggregate*` call to decide which `att_data` entries to
    /// drop before invoking `computeAggregatedSignatures`. See
    /// `ForkChoiceParams.min_aggregation_inputs`. Defaulted at the field
    /// level so test struct literals that don't care about the
    /// threshold can omit it.
    min_aggregation_inputs: u32 = types.default_min_aggregation_inputs,
    last_node_tick_time_ms: ?i64,

    const Self = @This();

    /// Thread-safe snapshot for observability
    pub const Snapshot = struct {
        head: ProtoNode,
        latest_justified: types.Checkpoint,
        latest_finalized: types.Checkpoint,
        safe_target_root: [32]u8,
        validator_count: u64,
        nodes: []ProtoNode,

        pub fn deinit(self: Snapshot, allocator: Allocator) void {
            allocator.free(self.nodes);
        }
    };

    /// Per-validator / per-subnet coverage captured from `latest_new_aggregated_payloads`
    /// immediately before an `acceptNewAttestationsUnlocked` merge.
    pub const SavedPreMergeCoverage = struct {
        slot: types.Slot,
        /// Per-validator presence (len == numValidators).
        seen: []bool,
        /// Per-subnet presence (len == attestation_committee_count).
        has_subnet: []bool,

        pub fn deinit(self: *SavedPreMergeCoverage, allocator: Allocator) void {
            allocator.free(self.seen);
            allocator.free(self.has_subnet);
        }
    };
    pub fn init(allocator: Allocator, opts: ForkChoiceParams) !Self {
        const anchor_block_header = try opts.anchorState.genStateBlockHeader(allocator);
        var anchor_block_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(
            types.BeamBlockHeader,
            anchor_block_header,
            &anchor_block_root,
            allocator,
        );

        const anchor_block = ProtoBlock{
            .slot = opts.anchorState.slot,
            .proposer_index = anchor_block_header.proposer_index,
            .blockRoot = anchor_block_root,
            .parentRoot = anchor_block_header.parent_root,
            .stateRoot = anchor_block_header.state_root,
            .timeliness = true,
            .confirmed = true,
        };
        const proto_array = try ProtoArray.init(allocator, anchor_block);
        const anchorCP = types.Checkpoint{ .slot = opts.anchorState.slot, .root = anchor_block_root };
        const fc_store = ForkChoiceStore{
            .slot_clock = zeam_utils.SlotTimeClock.init(
                opts.anchorState.slot * constants.INTERVALS_PER_SLOT,
                opts.anchorState.slot,
                0, // slotInterval is 0 at anchor: time is always a slot boundary
            ),
            .latest_justified = anchorCP,
            .latest_finalized = anchorCP,
        };
        const attestations = std.AutoHashMap(usize, AttestationTracker).init(allocator);
        const deltas: std.ArrayList(isize) = .empty;
        const attestation_signatures = SignaturesMap.init(allocator);
        const latest_new_aggregated_payloads = AggregatedPayloadsMap.init(allocator);
        const latest_known_aggregated_payloads = AggregatedPayloadsMap.init(allocator);
        const latest_block_aggregated_payloads = AggregatedPayloadsMap.init(allocator);

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
            .mutex = zeam_utils.SyncRwLock{},
            .attestation_signatures = attestation_signatures,
            .latest_new_aggregated_payloads = latest_new_aggregated_payloads,
            .latest_known_aggregated_payloads = latest_known_aggregated_payloads,
            .latest_block_aggregated_payloads = latest_block_aggregated_payloads,
            .latest_block_aggregated_payloads_slot = null,
            .signatures_mutex = .{},
            // Genesis (slot == 0) is immediately ready; checkpoint-sync / DB-restore anchors
            // (slot > 0) start in `initing` and become `ready` once the first real justified
            // checkpoint is observed through block processing.
            .status = if (opts.anchorState.slot == 0) .ready else .initing,
            .thread_pool = opts.thread_pool,
            .min_aggregation_inputs = opts.min_aggregation_inputs,
            .last_node_tick_time_ms = null,
        };
        if (fc.status == .initing) {
            fc.logger.info("[forkchoice] init: checkpoint-sync anchor at slot={d} — status=initing; awaiting first justified update before enabling validator duties", .{opts.anchorState.slot});
        } else {
            fc.logger.info("[forkchoice] init: genesis anchor — status=ready", .{});
        }
        // No lock needed during init - struct not yet accessible to other threads
        _ = try fc.updateHeadUnlocked();
        return fc;
    }

    /// Thread-safe snapshot for observability
    /// Holds shared lock only during copy, caller formats JSON lock-free
    pub fn snapshot(self: *Self, allocator: Allocator) !Snapshot {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();

        // Quick copy - ProtoNode has no pointer members, shallow copy is safe
        const nodes_copy = try allocator.alloc(ProtoNode, self.protoArray.nodes.items.len);
        @memcpy(nodes_copy, self.protoArray.nodes.items);

        // populate numBranches
        var node_natural_idx = nodes_copy.len;
        while (node_natural_idx > 0) {
            if (nodes_copy[node_natural_idx - 1].numBranches == null) {
                // leaf of the forkchoice tree is always a branch by itself
                nodes_copy[node_natural_idx - 1].numBranches = 1;
            }

            const numBranches = nodes_copy[node_natural_idx - 1].numBranches orelse @panic("invalid null num branches for node");
            if (nodes_copy[node_natural_idx - 1].parent) |parent_idx| {
                nodes_copy[parent_idx].numBranches = (nodes_copy[parent_idx].numBranches orelse 0) + numBranches;
            }

            node_natural_idx -= 1;
        }

        // Get the full ProtoNode for head from protoArray
        const head_idx = self.protoArray.indices.get(self.head.blockRoot) orelse {
            // Fallback: create a ProtoNode from ProtoBlock if not found
            const head_node = ProtoNode{
                .slot = self.head.slot,
                .proposer_index = self.head.proposer_index,
                .blockRoot = self.head.blockRoot,
                .parentRoot = self.head.parentRoot,
                .stateRoot = self.head.stateRoot,
                .timeliness = self.head.timeliness,
                .confirmed = self.head.confirmed,
                .parent = null,
                .weight = 0,
                .bestChild = null,
                .bestDescendant = null,
                .depth = 0,
                .nextSibling = 0,
                .firstChild = 0,
                .latestChild = 0,
                .numChildren = 0,
                .numBranches = 1,
            };
            return Snapshot{
                .head = head_node,
                .latest_justified = self.fcStore.latest_justified,
                .latest_finalized = self.fcStore.latest_finalized,
                .safe_target_root = self.safeTarget.blockRoot,
                .validator_count = self.config.genesis.numValidators(),
                .nodes = nodes_copy,
            };
        };

        return Snapshot{
            .head = self.protoArray.nodes.items[head_idx],
            .latest_justified = self.fcStore.latest_justified,
            .latest_finalized = self.fcStore.latest_finalized,
            .safe_target_root = self.safeTarget.blockRoot,
            .validator_count = self.config.genesis.numValidators(),
            .nodes = nodes_copy,
        };
    }

    pub fn deinit(self: *Self) void {
        self.protoArray.nodes.deinit(self.protoArray.allocator);
        self.protoArray.indices.deinit();
        self.attestations.deinit();
        self.deltas.deinit(self.allocator);

        self.signatures_mutex.lock();
        defer self.signatures_mutex.unlock();
        self.attestation_signatures.deinit();

        deinitAggregatedPayloadsMap(self.allocator, &self.latest_known_aggregated_payloads);
        deinitAggregatedPayloadsMap(self.allocator, &self.latest_new_aggregated_payloads);
        deinitAggregatedPayloadsMap(self.allocator, &self.latest_block_aggregated_payloads);
        if (self.saved_pre_merge_new_coverage) |*cov| cov.deinit(self.allocator);
    }

    fn isBlockTimely(self: *Self, blockDelayMs: usize) bool {
        _ = self;
        _ = blockDelayMs;
        return true;
    }

    pub fn isFinalizedDescendant(self: *Self, blockRoot: types.Root) bool {
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
    // Internal unlocked version - assumes caller holds lock
    fn getCanonicalViewUnlocked(self: *Self, canonical_view: *std.AutoHashMap(types.Root, void), targetAnchorRoot: types.Root, prevAnchorRootOrNull: ?types.Root) !void {
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
    // Internal unlocked version - assumes caller holds lock
    fn getCanonicalityAnalysisUnlocked(self: *Self, targetAnchorRoot: types.Root, prevAnchorRootOrNull: ?types.Root, canonicalViewOrNull: ?*std.AutoHashMap(types.Root, void)) ![3][]types.Root {
        var canonical_roots: std.ArrayList(types.Root) = .empty;
        var potential_canonical_roots: std.ArrayList(types.Root) = .empty;
        var non_canonical_roots: std.ArrayList(types.Root) = .empty;

        // get some info about previous and target anchors
        const prev_anchor_idx = if (prevAnchorRootOrNull) |prevAnchorRoot| (self.protoArray.indices.get(prevAnchorRoot) orelse return ForkChoiceError.InvalidAnchor) else 0;
        const target_anchor_idx = self.protoArray.indices.get(targetAnchorRoot) orelse return ForkChoiceError.InvalidTargetAnchor;
        const target_anchor_slot = self.protoArray.nodes.items[target_anchor_idx].slot;

        // get all canonical view of the chain finalized and unfinalized anchored at the targetAnchorRoot
        var canonical_blocks = canonicalViewOrNull orelse blk: {
            var local_view = std.AutoHashMap(types.Root, void).init(self.allocator);
            try self.getCanonicalViewUnlocked(&local_view, targetAnchorRoot, prevAnchorRootOrNull);
            break :blk &local_view;
        };

        // now we can split forkchoice into 3 parts (excluding target anchor)
        // traversing all the way from the bottom to the prev_anchor_idx
        var current_idx = self.protoArray.nodes.items.len - 1;
        while (current_idx >= prev_anchor_idx) {
            const current_node = self.protoArray.nodes.items[current_idx];
            if (canonical_blocks.contains(current_node.blockRoot)) {
                if (current_node.slot <= target_anchor_slot) {
                    self.logger.debug("adding confirmed canonical root={x} slot={d} index={d} parent={any}", .{
                        &current_node.blockRoot,
                        current_node.slot,
                        current_idx,
                        current_node.parent,
                    });
                    try canonical_roots.append(self.allocator, current_node.blockRoot);
                } else if (current_node.slot > target_anchor_slot) {
                    try potential_canonical_roots.append(self.allocator, current_node.blockRoot);
                }
            } else {
                try non_canonical_roots.append(self.allocator, current_node.blockRoot);
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
                self.logger.err("canonical root at index={d} {x}", .{
                    index,
                    &root,
                });
            }
            self.logger.err("targetAnchorRoot is {x}", .{&targetAnchorRoot});
            return ForkChoiceError.InvalidCanonicalTraversal;
        }

        const result = [_]([]types.Root){
            try canonical_roots.toOwnedSlice(self.allocator),
            //
            try potential_canonical_roots.toOwnedSlice(self.allocator),
            try non_canonical_roots.toOwnedSlice(self.allocator),
        };

        // only way to conditionally deinit locally allocated map created in a orelse block scope
        if (canonicalViewOrNull == null) {
            canonical_blocks.deinit();
        }
        return result;
    }

    /// Rebases the forkchoice tree to a new anchor, pruning non-canonical blocks.
    // Internal unlocked version - assumes caller holds lock
    fn rebaseUnlocked(self: *Self, targetAnchorRoot: types.Root, canonicalViewOrNull: ?*std.AutoHashMap(types.Root, void)) !void {
        const target_anchor_idx = self.protoArray.indices.get(targetAnchorRoot) orelse return ForkChoiceError.InvalidTargetAnchor;
        const target_anchor_slot = self.protoArray.nodes.items[target_anchor_idx].slot;
        const target_anchor_depth = self.protoArray.nodes.items[target_anchor_idx].depth;

        var canonical_view = canonicalViewOrNull orelse blk: {
            var local_view = std.AutoHashMap(types.Root, void).init(self.allocator);
            try self.getCanonicalViewUnlocked(&local_view, targetAnchorRoot, null);
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
            var current_node = self.protoArray.nodes.items[current_idx];
            // correct depth
            current_node.depth -= target_anchor_depth;

            // fix parent, anchor i.e. 0rth entry of forkchoice has no parent and no sibling
            if (current_idx == 0) {
                current_node.parent = null;
                current_node.nextSibling = 0;
            } else {
                // all other nodes should have parents, otherwise its an irrecoverable error as we have already
                // modified forkchoice and can't be restored
                const old_parent_idx = current_node.parent orelse @panic("invalid parent of the rebased unfinalized");
                const new_parent_idx = old_indices_to_new.get(old_parent_idx);
                current_node.parent = new_parent_idx;

                if (current_node.nextSibling != 0) {
                    current_node.nextSibling = old_indices_to_new.get(current_node.nextSibling) orelse @panic("invalid sibling of rebased unfinalized");
                }
            }

            // fix firstChild and latestChild
            if (current_node.latestChild != 0) {
                current_node.firstChild = old_indices_to_new.get(current_node.firstChild) orelse @panic("invalid first child of rebased tree");
                current_node.latestChild = old_indices_to_new.get(current_node.latestChild) orelse @panic("invalid latest child of rebaed tree");
            }

            // fix bestChild and descendant
            if (current_node.bestChild) |old_best_child_idx| {
                // we should be able to lookup new index otherwise its an irrecoverable error
                const new_best_child_idx = old_indices_to_new.get(old_best_child_idx) orelse @panic("invalid old index lookup for rebased best child");
                current_node.bestChild = new_best_child_idx;

                // If bestDescendant is null, keep it null (can happen when applyDeltas uses cutoff_weight
                // and the best branch has no node >= cutoff). See issue #545.
                if (current_node.bestDescendant) |old_best_descendant_idx| {
                    const new_best_descendant_idx = old_indices_to_new.get(old_best_descendant_idx) orelse @panic("invalid old index lookup for rebase best descendant");
                    current_node.bestDescendant = new_best_descendant_idx;
                }
                // else: bestDescendant remains null
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
    // Internal unlocked version - assumes caller holds lock
    fn getCanonicalAncestorAtDepthUnlocked(self: *Self, min_depth: usize) !ProtoBlock {
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

    // Internal unlocked version - assumes caller holds lock
    fn tickIntervalUnlocked(self: *Self, hasProposal: bool) !void {
        const time_now_ms: i64 = zeam_utils.unixTimestampMillis();
        if (self.last_node_tick_time_ms) |last| {
            const elapsed_s: f32 = @as(f32, @floatFromInt(time_now_ms - last)) / 1000.0;
            zeam_metrics.zeam_fork_choice_tick_interval_duration_seconds.record(elapsed_s);
            self.logger.debug("slot_interval={d} duration={d:.3}s", .{ self.fcStore.slot_clock.slotInterval.load(.monotonic), elapsed_s });
        }
        self.last_node_tick_time_ms = time_now_ms;

        const new_time = self.fcStore.slot_clock.time.fetchAdd(1, .monotonic) + 1;
        const currentInterval = new_time % constants.INTERVALS_PER_SLOT;
        self.fcStore.slot_clock.slotInterval.store(currentInterval, .monotonic);

        switch (currentInterval) {
            0 => {
                _ = self.fcStore.slot_clock.timeSlots.fetchAdd(1, .monotonic);
                // Accept new aggregated payloads only if a proposal exists for this slot.
                if (hasProposal) {
                    _ = try self.acceptNewAttestationsUnlocked();
                }
            },
            1 => {},
            2 => {},
            3 => {
                _ = try self.updateSafeTargetUnlocked();
            },
            4 => {
                _ = try self.acceptNewAttestationsUnlocked();
            },
            else => @panic("invalid interval"),
        }
        self.logger.debug("forkchoice ticked to time(intervals)={d} slot={d}", .{ self.fcStore.slot_clock.time.load(.monotonic), self.fcStore.slot_clock.timeSlots.load(.monotonic) });
    }

    // Internal unlocked version - assumes caller holds lock
    fn onIntervalUnlocked(self: *Self, time_intervals: usize, has_proposal: bool) !void {
        while (self.fcStore.slot_clock.time.load(.monotonic) < time_intervals) {
            try self.tickIntervalUnlocked(has_proposal and (self.fcStore.slot_clock.time.load(.monotonic) + 1) == time_intervals);
        }
    }

    // Internal unlocked version - assumes caller holds lock
    fn acceptNewAttestationsUnlocked(self: *Self) !ProtoBlock {
        // Capture counts outside lock scope for metrics update
        var known_payloads_count: usize = 0;
        var new_payloads_count: usize = 0;
        var payloads_updated = false;
        {
            // Keep payload migration synchronized with other signature/payload map writers.
            self.signatures_mutex.lock();
            defer self.signatures_mutex.unlock();

            if (self.latest_new_aggregated_payloads.count() > 0) {
                // Capture coverage of new payloads BEFORE merging them into known.
                // Saved as `saved_pre_merge_new_coverage` and used by
                // formatAggregationCoverageReport as the "prev_new" section.
                const vc: usize = @intCast(self.config.genesis.numValidators());
                const cc_u32 = self.config.spec.attestation_committee_count;
                if (vc > 0 and cc_u32 > 0) {
                    const cc: usize = @intCast(cc_u32);
                    // Determine slot from the first entry key.
                    var payload_slot: types.Slot = 0;
                    {
                        var it_s = self.latest_new_aggregated_payloads.iterator();
                        if (it_s.next()) |first| payload_slot = first.key_ptr.slot;
                    }
                    const new_seen = try self.allocator.alloc(bool, vc);
                    var coverage_saved = false;
                    errdefer if (!coverage_saved) self.allocator.free(new_seen);
                    const new_has_subnet = try self.allocator.alloc(bool, cc);
                    errdefer if (!coverage_saved) self.allocator.free(new_has_subnet);
                    const dummy_combined_seen = try self.allocator.alloc(bool, vc);
                    defer self.allocator.free(dummy_combined_seen);
                    const dummy_combined_has = try self.allocator.alloc(bool, cc);
                    defer self.allocator.free(dummy_combined_has);
                    @memset(new_seen, false);
                    @memset(new_has_subnet, false);
                    @memset(dummy_combined_seen, false);
                    @memset(dummy_combined_has, false);

                    collectCoverageFromPayloads(
                        &self.latest_new_aggregated_payloads,
                        payload_slot,
                        cc_u32,
                        new_seen,
                        dummy_combined_seen,
                        new_has_subnet,
                        dummy_combined_has,
                    );

                    if (self.saved_pre_merge_new_coverage) |*old| old.deinit(self.allocator);
                    self.saved_pre_merge_new_coverage = .{
                        .slot = payload_slot,
                        .seen = new_seen,
                        .has_subnet = new_has_subnet,
                    };
                    coverage_saved = true;
                }

                var it = self.latest_new_aggregated_payloads.iterator();
                while (it.next()) |entry| {
                    const att_data = entry.key_ptr.*;
                    const source_list = entry.value_ptr;

                    const gop = try self.latest_known_aggregated_payloads.getOrPut(att_data);
                    if (!gop.found_existing) {
                        gop.value_ptr.* = .empty;
                    }

                    // Ensure all required capacity up-front so the move is non-failing.
                    try gop.value_ptr.ensureUnusedCapacity(self.allocator, source_list.items.len);
                    for (source_list.items) |stored| {
                        gop.value_ptr.appendAssumeCapacity(stored);
                    }

                    // Source list buffer no longer needed after ownership transfer.
                    source_list.deinit(self.allocator);
                    source_list.* = .empty;
                }
                self.latest_new_aggregated_payloads.clearAndFree();
                // Capture counts for metrics update outside lock
                known_payloads_count = self.latest_known_aggregated_payloads.count();
                new_payloads_count = self.latest_new_aggregated_payloads.count();
                payloads_updated = true;
            }
        }
        // Update fork-choice store gauges after promotion (outside lock scope)
        if (payloads_updated) {
            zeam_metrics.metrics.lean_latest_known_aggregated_payloads.set(@intCast(known_payloads_count));
            zeam_metrics.metrics.lean_latest_new_aggregated_payloads.set(@intCast(new_payloads_count));
        }

        // Promote latestNew → latestKnown in attestation tracker.
        // Attestations that were "new" (gossip) are now "known" (accepted).
        //
        // The migration is a union, not a replacement: a validator's known vote
        // persists until a strictly newer vote overrides it (known votes are
        // pruned only on finalization, never wiped per tick). This matches both
        // leanSpec's accumulating known pool and LMD-GHOST's "latest message"
        // rule. An unconditional `latestKnown = latestNew` would erase a known
        // vote whenever the validator has no pending gossip vote — which happens
        // for a validator whose latest vote arrived via a block's own attestation
        // (recorded directly in latestKnown), with no matching latestNew.
        for (0..self.config.genesis.numValidators()) |validator_id| {
            var tracker = self.attestations.get(validator_id) orelse continue;
            const new_att = tracker.latestNew orelse continue;
            const known_slot = (tracker.latestKnown orelse ProtoAttestation{}).slot;
            if (tracker.latestKnown == null or new_att.slot > known_slot) {
                tracker.latestKnown = new_att;
                try self.attestations.put(validator_id, tracker);
            }
        }

        return self.updateHeadUnlocked();
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

    // Internal unlocked version - assumes caller holds lock
    pub const ProposalAttestationsResult = struct {
        attestations: types.AggregatedAttestations,
        signatures: types.Type1ProofList,
    };

    /// Checks whether `slot` is justified under the given tracking state,
    /// matching leanSpec `build_block`'s `current_justified_slots.is_slot_justified`
    /// (leanSpec commit 00556d8).
    /// Returns `false` (never an error) when `slot` is beyond the current
    /// justified_slots window — those slots are simply not yet justified.
    /// Slots at or before `finalized_slot` are implicitly justified (return `true`).
    fn isSlotJustifiedForBuild(
        finalized_slot: types.Slot,
        justified_slots: *const types.JustifiedSlots,
        slot: types.Slot,
    ) bool {
        if (slot <= finalized_slot) return true;
        // idx = slot - (finalized_slot + 1)
        const idx: usize = @intCast(slot - finalized_slot - 1);
        if (idx >= justified_slots.len()) return false;
        return justified_slots.get(idx) catch false;
    }

    /// Mirrors leanSpec `_attestation_data_matches_chain` (leanSpec commit 00556d8).
    /// Checks whether `att_data`'s source and target roots are consistent with
    /// the *extended* historical block hashes view — i.e. `state.historical_block_hashes`
    /// as it would appear after `process_block_header` on the candidate block:
    ///
    ///   extended = historical_block_hashes + [parent_root] + [ZERO_HASH] * num_empty_slots
    ///
    /// Receives the pre-state's `historical_block_hashes` and the candidate
    /// `parent_root` separately to avoid an allocation; `hist_len` is computed
    /// internally from the slice length.
    /// Also rejects attestations whose source or target root is the zero hash.
    fn attestationDataMatchesChainExtended(
        historical_block_hashes: *const types.HistoricalBlockHashes,
        parent_root: [32]u8,
        att_data: types.AttestationData,
    ) bool {
        const ZERO_HASH = types.ZERO_HASH;
        if (std.mem.eql(u8, &att_data.source.root, &ZERO_HASH)) return false;
        if (std.mem.eql(u8, &att_data.target.root, &ZERO_HASH)) return false;

        const hist_len: u64 = @intCast(historical_block_hashes.len());
        const hist_slice = historical_block_hashes.constSlice();
        const source_slot: u64 = att_data.source.slot;
        const target_slot: u64 = att_data.target.slot;

        // Resolve a slot index against the extended view:
        //   [0, hist_len)  → historical_block_hashes[i]
        //   hist_len       → parent_root (the parent block's slot)
        //   > hist_len     → ZERO_HASH  (empty slots; will fail equality check)
        const stored_source: [32]u8 = if (source_slot < hist_len)
            hist_slice[source_slot]
        else if (source_slot == hist_len)
            parent_root
        else
            ZERO_HASH;

        const stored_target: [32]u8 = if (target_slot < hist_len)
            hist_slice[target_slot]
        else if (target_slot == hist_len)
            parent_root
        else
            ZERO_HASH;

        return std.mem.eql(u8, &att_data.source.root, &stored_source) and
            std.mem.eql(u8, &att_data.target.root, &stored_target);
    }

    fn getProposalAttestationsUnlocked(
        self: *Self,
        pre_state: *const types.BeamState,
        slot: types.Slot,
        proposer_index: types.ValidatorIndex,
        parent_root: [32]u8,
    ) !ProposalAttestationsResult {
        var agg_attestations = try types.AggregatedAttestations.init(self.allocator);
        var agg_att_cleanup = true;
        errdefer if (agg_att_cleanup) {
            for (agg_attestations.slice()) |*att| att.deinit();
            agg_attestations.deinit();
        };

        var attestation_signatures = try types.Type1ProofList.init(self.allocator);
        var agg_sig_cleanup = true;
        errdefer if (agg_sig_cleanup) {
            for (attestation_signatures.slice()) |*sig| sig.deinit();
            attestation_signatures.deinit();
        };

        // Fixed-point attestation collection with greedy proof selection.
        //
        // leanSpec `build_block` (commit 00556d8): instead of filtering by a single
        // justified root, we now accept any attestation whose *source slot* is marked
        // justified in `current_justified_slots`. This allows older-but-still-justified
        // sources to appear in a block, not just the latest justified checkpoint.
        //
        // The extended historical block hashes view (pre_state hashes + parent_root +
        // zero-hashes for empty slots) is used to validate source/target roots without
        // running the full STF first.
        //
        // The loop restarts whenever justification OR finalization advances so we can
        // pick up attestations that become valid only after a justification update.
        var current_finalized_slot: types.Slot = pre_state.latest_finalized.slot;
        // Spec note (leanSpec d0c5030 / commit 00556d8): when building on top of genesis
        // (pre_state.latest_block_header.slot == 0), process_block_header would set
        // latest_justified.root = parent_root. The old code applied that same derivation
        // eagerly so the source-root filter matched. With the new slot-based filter we no
        // longer need the root at all — we only test whether the source *slot* is justified.
        // At genesis, slot 0 <= finalized_slot 0 so isSlotJustifiedForBuild returns true
        // unconditionally, which is correct. The one observable difference is that the first
        // STF run will see justified_changed == true (pre_state has ZERO_HASH root; post-state
        // has parent_root) and do one extra loop iteration. That iteration finds no new
        // entries (genesis self-votes are already in processed_att_data) and breaks, so the
        // output is identical — the extra iteration is intentionally accepted in exchange for
        // simpler code with no genesis special-case.
        var current_justified: types.Checkpoint = pre_state.latest_justified;

        // Clone pre_state.justified_slots so we can update it across loop iterations
        // without touching the immutable pre_state.
        var current_justified_slots: types.JustifiedSlots = undefined;
        try types.sszClone(self.allocator, types.JustifiedSlots, pre_state.justified_slots, &current_justified_slots);
        defer current_justified_slots.deinit();

        var processed_att_data = std.AutoHashMap(types.AttestationData, void).init(self.allocator);
        defer processed_att_data.deinit();

        var child_payloads_consumed: usize = 0;

        // Selection + FFI below run on an owned copy: the live pool is mutated under
        // signatures_mutex by other threads, so iterating it under only the fork-choice shared
        // mutex would race. Lock order fc-mutex(shared) then signatures_mutex avoids deadlock.
        var known_payloads_snapshot = snapshot_blk: {
            self.signatures_mutex.lock();
            defer self.signatures_mutex.unlock();
            break :snapshot_blk try cloneAggregatedPayloadsMap(self.allocator, &self.latest_known_aggregated_payloads);
        };
        defer deinitAggregatedPayloadsMap(self.allocator, &known_payloads_snapshot);

        while (true) {
            const select_start_ns = zeam_utils.monotonicTimestampNs();

            // Find attestation_data entries whose source slot is justified on this chain,
            // that reference blocks we know about, and whose target is not yet justified.
            // Collect and sort by target slot for deterministic processing order.
            const MapEntry = struct {
                att_data: *types.AttestationData,
                payloads: *types.AggregatedPayloadsList,
            };
            var sorted_entries: std.ArrayList(MapEntry) = .empty;
            defer sorted_entries.deinit(self.allocator);

            var payload_it = known_payloads_snapshot.iterator();
            while (payload_it.next()) |entry| {
                const att_data = entry.key_ptr;

                // Source slot must already be justified on this chain (leanSpec build_block).
                if (!isSlotJustifiedForBuild(current_finalized_slot, &current_justified_slots, att_data.source.slot)) continue;

                // Source and target roots must match our chain's historical block hashes
                // (extended to include parent_root and empty-slot zeros up to slot-1).
                // Also rejects zero-hash source or target roots inline.
                if (!attestationDataMatchesChainExtended(&pre_state.historical_block_hashes, parent_root, att_data.*)) continue;

                // Skip attestations whose target slot is already justified on this chain,
                // except for genesis self-votes used for fork-choice bootstrapping.
                const is_genesis_self_vote = att_data.source.slot == 0 and att_data.target.slot == 0;
                if (!is_genesis_self_vote and isSlotJustifiedForBuild(current_finalized_slot, &current_justified_slots, att_data.target.slot)) continue;

                if (!self.protoArray.indices.contains(att_data.head.root)) continue;
                // Spec divergence (intentional): leanSpec removed the processed_att_data
                // dedup in this commit, relying on a final proof_groups compaction pass.
                // Zeam keeps it because we compact *inside* the loop and each AttestationData
                // is processed exactly once per outer iteration. Removing the skip here would
                // re-select the same entry on loop restarts, producing duplicate attestations
                // in the candidate without changing the final justified checkpoint.
                if (processed_att_data.contains(att_data.*)) continue;
                try sorted_entries.append(self.allocator, .{
                    .att_data = att_data,
                    .payloads = entry.value_ptr,
                });
            }

            // leanSpec build_block sorts purely by target.slot (forks/lstar/spec.py); the
            // att_data.slot tiebreak only makes the unstable sort deterministic for equal targets.
            std.mem.sort(MapEntry, sorted_entries.items, {}, struct {
                fn lessThan(_: void, a: MapEntry, b: MapEntry) bool {
                    if (a.att_data.target.slot == b.att_data.target.slot) {
                        return a.att_data.slot < b.att_data.slot;
                    }
                    return a.att_data.target.slot < b.att_data.target.slot;
                }
            }.lessThan);

            const found_entries = sorted_entries.items.len > 0;

            for (sorted_entries.items) |map_entry| {
                // Limit the number of distinct AttestationData entries per block.
                if (processed_att_data.count() >= self.config.spec.max_attestations_data) break;

                try processed_att_data.put(map_entry.att_data.*, {});

                const att_data = map_entry.att_data.*;
                const payloads = map_entry.payloads;

                // Greedy proof selection: each iteration picks the proof covering
                // the most uncovered validators until all are covered.
                var covered = try std.DynamicBitSet.initEmpty(self.allocator, 0);
                defer covered.deinit();

                while (true) {
                    var best_proof: ?*const types.TypeOneMultiSignature = null;
                    var best_new_coverage: usize = 0;

                    for (payloads.items) |*stored| {
                        var new_coverage: usize = 0;
                        for (0..stored.proof.participants.len()) |i| {
                            if (stored.proof.participants.get(i) catch false) {
                                if (i >= covered.capacity() or !covered.isSet(i)) {
                                    new_coverage += 1;
                                }
                            }
                        }
                        if (new_coverage > best_new_coverage) {
                            best_new_coverage = new_coverage;
                            best_proof = &stored.proof;
                        }
                    }

                    if (best_proof == null or best_new_coverage == 0) break;

                    var cloned_proof: types.TypeOneMultiSignature = undefined;
                    try types.sszClone(self.allocator, types.TypeOneMultiSignature, best_proof.?.*, &cloned_proof);
                    errdefer cloned_proof.deinit();

                    var att_bits: types.AggregationBits = undefined;
                    try types.sszClone(self.allocator, types.AggregationBits, cloned_proof.participants, &att_bits);
                    errdefer att_bits.deinit();

                    for (0..cloned_proof.participants.len()) |i| {
                        if (cloned_proof.participants.get(i) catch false) {
                            if (i >= covered.capacity()) {
                                try covered.resize(i + 1, false);
                            }
                            covered.set(i);
                        }
                    }

                    try agg_attestations.append(.{ .aggregation_bits = att_bits, .data = att_data });
                    try attestation_signatures.append(cloned_proof);
                    child_payloads_consumed += 1;
                }
            }

            observeProposalBuildPhase("select_payloads", select_start_ns);

            if (!found_entries) break;

            // Compact: merge proofs sharing the same AttestationData into one
            // using recursive children aggregation, so each AttestationData
            // appears at most once.
            const compact_start_ns = zeam_utils.monotonicTimestampNs();
            const compact_timer = zeam_metrics.zeam_compact_attestations_time_seconds.start();
            const compacted = try types.compactAttestations(
                self.allocator,
                &agg_attestations,
                &attestation_signatures,
                &pre_state.validators,
                self.thread_pool,
            );
            _ = compact_timer.observe();
            zeam_metrics.metrics.zeam_compact_attestations_input_total.incrBy(@intCast(agg_attestations.constSlice().len));
            agg_attestations = compacted.attestations;
            attestation_signatures = compacted.signatures;
            zeam_metrics.metrics.zeam_compact_attestations_output_total.incrBy(@intCast(agg_attestations.constSlice().len));
            observeProposalBuildPhase("compact", compact_start_ns);

            const stf_start_ns = zeam_utils.monotonicTimestampNs();

            // Build candidate block with all accumulated attestations and apply STF
            // to check if justification changed.
            var candidate_atts = try types.AggregatedAttestations.init(self.allocator);
            defer {
                for (candidate_atts.slice()) |*att| att.deinit();
                candidate_atts.deinit();
            }

            for (agg_attestations.constSlice()) |agg_att| {
                var cloned_bits: types.AggregationBits = undefined;
                try types.sszClone(self.allocator, types.AggregationBits, agg_att.aggregation_bits, &cloned_bits);
                errdefer cloned_bits.deinit();
                try candidate_atts.append(.{ .aggregation_bits = cloned_bits, .data = agg_att.data });
            }

            const candidate_block = types.BeamBlock{
                .slot = slot,
                .proposer_index = proposer_index,
                .parent_root = parent_root,
                .state_root = std.mem.zeroes([32]u8),
                .body = .{ .attestations = candidate_atts },
            };

            var candidate_state: types.BeamState = undefined;
            try types.sszClone(self.allocator, types.BeamState, pre_state.*, &candidate_state);
            defer candidate_state.deinit();

            try candidate_state.process_slots(self.allocator, slot, self.logger);
            try candidate_state.process_block(self.allocator, candidate_block, self.logger, null);

            // Restart if justification or finalization advanced (leanSpec build_block).
            // When either changes, update all tracking state and re-scan for newly
            // eligible attestations (older sources whose slots are now justified, or
            // targets that were previously already-justified but aren't after a finality
            // shift).
            const justified_changed = !std.mem.eql(u8, &candidate_state.latest_justified.root, &current_justified.root) or
                candidate_state.latest_justified.slot != current_justified.slot;
            const finalized_changed = candidate_state.latest_finalized.slot != current_finalized_slot;
            if (justified_changed or finalized_changed) {
                observeProposalBuildPhase("stf_simulate", stf_start_ns);
                current_justified = candidate_state.latest_justified;
                current_finalized_slot = candidate_state.latest_finalized.slot;
                // Swap in the updated justified_slots (clone first so candidate_state
                // can be safely deinitialized at end of this iteration).
                var new_justified_slots: types.JustifiedSlots = undefined;
                try types.sszClone(self.allocator, types.JustifiedSlots, candidate_state.justified_slots, &new_justified_slots);
                current_justified_slots.deinit();
                current_justified_slots = new_justified_slots;
                continue;
            }

            observeProposalBuildPhase("stf_simulate", stf_start_ns);

            // Justification and finalization unchanged - block production done.
            break;
        }

        zeam_metrics.metrics.lean_block_proposal_attestation_builds_total.incr();
        zeam_metrics.metrics.lean_block_proposal_child_payloads_consumed_total.incrBy(@intCast(child_payloads_consumed));
        zeam_metrics.lean_block_proposal_attestation_data_selected.record(@floatFromInt(processed_att_data.count()));
        zeam_metrics.lean_block_proposal_aggregates_selected.record(@floatFromInt(attestation_signatures.len()));

        self.logBlockProposalPayloadCoverage(slot, &agg_attestations);

        agg_att_cleanup = false;
        agg_sig_cleanup = false;
        return .{ .attestations = agg_attestations, .signatures = attestation_signatures };
    }

    /// Log coverage attribution for the attestations selected while building
    /// a block proposal. `payloads` means validators covered by known
    /// aggregated payload proofs; `gossip` means validators covered by
    /// gossiped single attestations that were not already covered by those
    /// payload proofs; `combined` is the actual block attestation coverage.
    fn logBlockProposalPayloadCoverage(self: *Self, slot: types.Slot, proposal_attestations: *const types.AggregatedAttestations) void {
        const validator_count: usize = @intCast(self.config.genesis.numValidators());
        if (validator_count == 0) return;
        const committee_count_u32 = self.config.spec.attestation_committee_count;
        if (committee_count_u32 == 0) return;
        const committee_count: usize = @intCast(committee_count_u32);

        const payload_seen = self.allocator.alloc(bool, validator_count) catch return;
        defer self.allocator.free(payload_seen);
        const gossip_available = self.allocator.alloc(bool, validator_count) catch return;
        defer self.allocator.free(gossip_available);
        const final_seen = self.allocator.alloc(bool, validator_count) catch return;
        defer self.allocator.free(final_seen);
        const final_has_subnet = self.allocator.alloc(bool, committee_count) catch return;
        defer self.allocator.free(final_has_subnet);
        const proposal_payload_seen = self.allocator.alloc(bool, validator_count) catch return;
        defer self.allocator.free(proposal_payload_seen);
        const proposal_payload_has_subnet = self.allocator.alloc(bool, committee_count) catch return;
        defer self.allocator.free(proposal_payload_has_subnet);
        const proposal_gossip_seen = self.allocator.alloc(bool, validator_count) catch return;
        defer self.allocator.free(proposal_gossip_seen);
        const proposal_gossip_has_subnet = self.allocator.alloc(bool, committee_count) catch return;
        defer self.allocator.free(proposal_gossip_has_subnet);

        @memset(payload_seen, false);
        @memset(gossip_available, false);
        @memset(final_seen, false);
        @memset(final_has_subnet, false);
        @memset(proposal_payload_seen, false);
        @memset(proposal_payload_has_subnet, false);
        @memset(proposal_gossip_seen, false);
        @memset(proposal_gossip_has_subnet, false);

        for (proposal_attestations.constSlice()) |agg_att| {
            collectCoverageFromAggregatedAttestation(
                agg_att,
                committee_count_u32,
                final_seen,
                final_has_subnet,
            );
            collectSourceCoverageFromPayloadsForData(
                &self.latest_known_aggregated_payloads,
                agg_att.data,
                committee_count_u32,
                payload_seen,
                gossip_available,
            );
        }

        for (final_seen, 0..) |is_final, validator_index| {
            if (!is_final) continue;
            const subnet_id = types.computeSubnetId(@intCast(validator_index), committee_count_u32) catch continue;
            const subnet_index: usize = @intCast(subnet_id);
            if (subnet_index >= committee_count) continue;

            if (payload_seen[validator_index]) {
                proposal_payload_seen[validator_index] = true;
                proposal_payload_has_subnet[subnet_index] = true;
            } else if (gossip_available[validator_index]) {
                proposal_gossip_seen[validator_index] = true;
                proposal_gossip_has_subnet[subnet_index] = true;
            }
        }

        var has_any = false;
        for (final_seen) |seen| {
            if (seen) {
                has_any = true;
                break;
            }
        }

        recordAggregateCoverageMetrics("proposal_payloads", proposal_payload_seen, proposal_payload_has_subnet, committee_count_u32);
        recordAggregateCoverageMetrics("proposal_gossip", proposal_gossip_seen, proposal_gossip_has_subnet, committee_count_u32);
        recordAggregateCoverageMetrics("proposal_combined", final_seen, final_has_subnet, committee_count_u32);

        if (!has_any) {
            self.logger.info("block proposal slot={d}: attestation aggregate coverage=none", .{slot});
            return;
        }

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        appendFmt(self.allocator, &out, "block proposal slot={d}: attestation aggregate coverage: ", .{slot}) catch return;
        appendCoverageSection(self.allocator, &out, "payloads", proposal_payload_seen, proposal_payload_has_subnet, validator_count, committee_count_u32) catch return;
        out.appendSlice(self.allocator, " | ") catch return;
        appendCoverageSection(self.allocator, &out, "gossip", proposal_gossip_seen, proposal_gossip_has_subnet, validator_count, committee_count_u32) catch return;
        out.appendSlice(self.allocator, " | ") catch return;
        appendCoverageSection(self.allocator, &out, "combined", final_seen, final_has_subnet, validator_count, committee_count_u32) catch return;

        const combined_covered = countSeen(final_seen);
        const payload_covered = countSeen(proposal_payload_seen);
        const gossip_covered = countSeen(proposal_gossip_seen);
        appendFmt(self.allocator, &out, " | network={d}/{d}({d:.2}%) | source_validators=payloads:{d} gossip:{d}", .{
            combined_covered,
            validator_count,
            coveragePct(combined_covered, validator_count),
            payload_covered,
            gossip_covered,
        }) catch return;
        self.logger.info("{s}", .{out.items});
    }

    // Internal unlocked version - assumes caller holds lock
    fn getAttestationTargetUnlocked(self: *Self) !types.Checkpoint {
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

    // Internal unlocked version - assumes caller holds lock
    // Always reads from the per-validator attestation tracker (sole source of truth for fork choice).
    fn computeDeltasUnlocked(self: *Self, from_known: bool) ![]isize {
        // prep the deltas data structure
        while (self.deltas.items.len < self.protoArray.nodes.items.len) {
            try self.deltas.append(self.allocator, 0);
        }
        for (0..self.deltas.items.len) |i| {
            self.deltas.items[i] = 0;
        }
        // balances are right now same for the dummy chain and each weighing 1
        const validatorWeight = 1;

        var delta_iter = self.attestations.iterator();
        while (delta_iter.next()) |entry| {
            if (entry.value_ptr.appliedIndex) |applied_index| {
                self.deltas.items[applied_index] -= validatorWeight;
            }
            entry.value_ptr.appliedIndex = null;

            const latest_attestation = if (from_known)
                entry.value_ptr.latestKnown
            else
                entry.value_ptr.latestNew;

            if (latest_attestation) |delta_attestation| {
                self.deltas.items[delta_attestation.index] += validatorWeight;
                entry.value_ptr.appliedIndex = delta_attestation.index;
            }
        }

        return self.deltas.items;
    }

    // Internal unlocked version - assumes caller holds lock
    fn computeFCHeadUnlocked(self: *Self, from_known: bool, cutoff_weight: u64) !ProtoBlock {
        const deltas = try self.computeDeltasUnlocked(from_known);
        try self.protoArray.applyDeltasUnlocked(deltas, cutoff_weight);

        // head is the best descendant of latest justified
        const justified_idx = self.protoArray.indices.get(self.fcStore.latest_justified.root) orelse return ForkChoiceError.InvalidJustifiedRoot;
        const justified_node = self.protoArray.nodes.items[justified_idx];

        // if case of no best descendant latest justified is always best descendant
        const best_descendant_idx = justified_node.bestDescendant orelse justified_idx;
        const best_descendant = self.protoArray.nodes.items[best_descendant_idx];

        self.logger.debug("computeFCHead from_known={} cutoff_weight={d} deltas_len={d} justified_node={f} best_descendant_idx={d}", .{
            from_known,
            cutoff_weight,
            deltas.len,
            justified_node,
            best_descendant_idx,
        });

        const fcHead = zeam_utils.Cast(ProtoBlock, best_descendant);
        return fcHead;
    }

    // Internal unlocked version - assumes caller holds lock
    fn updateHeadUnlocked(self: *Self) !ProtoBlock {
        const previous_head = self.head;
        self.head = try self.computeFCHeadUnlocked(true, 0);

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

    // Internal unlocked version - assumes caller holds lock
    fn updateSafeTargetUnlocked(self: *Self) !ProtoBlock {
        const cutoff_weight = try std.math.divCeil(u64, 2 * self.config.genesis.numValidators(), 3);
        const safe_target = try self.computeFCHeadUnlocked(false, cutoff_weight);

        // Safe target regression is a legitimate fork-choice outcome, not a
        // bug: the deepest 2/3-supported descendant of `latest_justified` can
        // move to a shallower slot when attestation weights shift across
        // branches or when `latest_justified` itself advances to a different
        // subtree. Previously this returned `InvalidSafeTargetCompute`, which
        // aborted the interval-3 tick and wedged the node's time loop on
        // devnet-4 whenever target divergence produced a shallower
        // 2/3-supermajority subtree. Accept the new value and surface the
        // regression via a warn-level log so operators retain visibility.
        if (safe_target.slot < self.safeTarget.slot) {
            self.logger.warn("safe target regressed new={d} < current={d}; accepting new value", .{
                safe_target.slot,
                self.safeTarget.slot,
            });
        }

        self.safeTarget = safe_target;
        zeam_metrics.metrics.lean_safe_target_slot.set(self.safeTarget.slot);
        return self.safeTarget;
    }

    /// Checks if potential_ancestor is an ancestor of descendant by walking up parent chain.
    /// Populates ancestors_map with all visited nodes for reuse in calculateReorgDepth.
    /// Note: descendant must exist in protoArray (it comes from computeFCHead which retrieves
    /// it directly from protoArray.nodes). If not found, it indicates a bug in the code.
    fn isAncestorOf(self: *Self, potential_ancestor: types.Root, descendant: types.Root, ancestors_map: *std.AutoHashMap(types.Root, void)) bool {
        // descendant is guaranteed to exist - it comes from computeFCHeadUnlocked() which
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

    // Internal unlocked version - assumes caller holds lock
    fn onSignedAttestationUnlocked(self: *Self, signed_attestation: types.SignedAttestation) !void {
        // Attestation validation is done by the caller (chain layer)
        // This function assumes the attestation has already been validated

        const attestation_data = signed_attestation.message;
        const validator_id = signed_attestation.validator_id;
        const attestation_slot = attestation_data.slot;

        var attestation_sigs_count: usize = 0;
        {
            self.signatures_mutex.lock();
            defer self.signatures_mutex.unlock();

            try self.attestation_signatures.addSignature(attestation_data, validator_id, .{
                .slot = attestation_slot,
                .signature = signed_attestation.signature,
            });
            attestation_sigs_count = self.attestation_signatures.count();
        }
        // Update metric outside lock scope
        zeam_metrics.metrics.lean_gossip_signatures.set(@intCast(attestation_sigs_count));

        const attestation = types.Attestation{
            .validator_id = validator_id,
            .data = attestation_data,
        };
        try self.onAttestationUnlocked(attestation, false);
    }

    pub fn onAttestationUnlocked(self: *Self, attestation: types.Attestation, is_from_block: bool) !void {
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

                // leanSpec PR #680 keeps the gossip ("new") and on-chain
                // ("known") pools strictly separate: `update_safe_target`
                // operates on the new pool only, while head selection uses
                // the known pool. Mirroring `latestKnown → latestNew` here
                // would smuggle on-chain weight back into the safe-target
                // computation and break the
                // `test_safe_target_ignores_known_pool_at_interval_3`
                // contract from the spec test vectors.
            }
        } else {
            // leanSpec allows attestations up to 1 slot in the future:
            //   assert data.slot <= current_slot + Slot(1)
            // In production, chain.validateAttestationData enforces the stricter gossip
            // check (data.slot <= current_slot) upstream.
            if (attestation_slot > self.fcStore.slot_clock.timeSlots.load(.monotonic) + 1) {
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

    /// Store an aggregated signature proof keyed by AttestationData.
    /// If is_from_block, stores in latest_known_aggregated_payloads (immediately available for block building).
    /// Otherwise, stores in latest_new_aggregated_payloads (promoted to known via periodic ticks).
    pub fn storeAggregatedPayload(
        self: *Self,
        attestation_data: *const types.AttestationData,
        proof: types.TypeOneMultiSignature,
        is_from_block: bool,
    ) !void {
        var cloned_proof: types.TypeOneMultiSignature = undefined;
        try types.sszClone(self.allocator, types.TypeOneMultiSignature, proof, &cloned_proof);
        var cloned_proof_owned = true;
        errdefer if (cloned_proof_owned) cloned_proof.deinit();

        {
            self.signatures_mutex.lock();
            defer self.signatures_mutex.unlock();

            const target_map = if (is_from_block)
                &self.latest_known_aggregated_payloads
            else
                &self.latest_new_aggregated_payloads;

            const gop = try target_map.getOrPut(attestation_data.*);
            if (!gop.found_existing) {
                gop.value_ptr.* = .empty;
            }

            try gop.value_ptr.append(self.allocator, .{
                .slot = attestation_data.slot,
                .proof = cloned_proof,
            });
            cloned_proof_owned = false;

            if (is_from_block) {
                if (self.latest_block_aggregated_payloads_slot == null or self.latest_block_aggregated_payloads_slot.? != attestation_data.slot) {
                    deinitAggregatedPayloadsMap(self.allocator, &self.latest_block_aggregated_payloads);
                    self.latest_block_aggregated_payloads = AggregatedPayloadsMap.init(self.allocator);
                    self.latest_block_aggregated_payloads_slot = attestation_data.slot;
                }

                var block_proof: types.TypeOneMultiSignature = undefined;
                try types.sszClone(self.allocator, types.TypeOneMultiSignature, proof, &block_proof);
                var block_proof_owned = true;
                errdefer if (block_proof_owned) block_proof.deinit();

                const block_gop = try self.latest_block_aggregated_payloads.getOrPut(attestation_data.*);
                if (!block_gop.found_existing) {
                    block_gop.value_ptr.* = .empty;
                }
                try block_gop.value_ptr.append(self.allocator, .{
                    .slot = attestation_data.slot,
                    .proof = block_proof,
                });
                block_proof_owned = false;
            }
        }
    }

    /// Format the full per-slot attestation aggregate coverage report.
    ///
    /// Sections:
    ///   prev_new  – coverage saved just before the last acceptNewAttestationsUnlocked merge
    ///               (represents the previous slot's new payloads that were accepted)
    ///   late      – current latest_new_aggregated_payloads for `slot`
    ///               (payloads that arrived after the last merge — late arrivals)
    ///   block     – payloads observed in the most-recently processed block
    ///   combined  – union of all three
    ///   diff      – validator-coverage delta between block and prev_new
    ///   network   – combined / total validators
    pub fn formatAggregationCoverageReport(self: *Self, allocator: Allocator, slot: types.Slot) !?[]u8 {
        const validator_count: usize = @intCast(self.config.genesis.numValidators());
        if (validator_count == 0) return null;

        const committee_count_u32 = self.config.spec.attestation_committee_count;
        if (committee_count_u32 == 0) return null;
        const committee_count: usize = @intCast(committee_count_u32);

        // Work buffers for each section.
        const prev_new_seen = try allocator.alloc(bool, validator_count);
        defer allocator.free(prev_new_seen);
        const prev_new_has_subnet = try allocator.alloc(bool, committee_count);
        defer allocator.free(prev_new_has_subnet);
        const late_seen = try allocator.alloc(bool, validator_count);
        defer allocator.free(late_seen);
        const late_has_subnet = try allocator.alloc(bool, committee_count);
        defer allocator.free(late_has_subnet);
        const block_seen = try allocator.alloc(bool, validator_count);
        defer allocator.free(block_seen);
        const block_has_subnet = try allocator.alloc(bool, committee_count);
        defer allocator.free(block_has_subnet);
        const combined_seen = try allocator.alloc(bool, validator_count);
        defer allocator.free(combined_seen);
        const combined_has_subnet = try allocator.alloc(bool, committee_count);
        defer allocator.free(combined_has_subnet);

        @memset(prev_new_seen, false);
        @memset(prev_new_has_subnet, false);
        @memset(late_seen, false);
        @memset(late_has_subnet, false);
        @memset(block_seen, false);
        @memset(block_has_subnet, false);
        @memset(combined_seen, false);
        @memset(combined_has_subnet, false);

        self.signatures_mutex.lock();
        defer self.signatures_mutex.unlock();

        // Fill prev_new from the coverage saved before the last merge (if slot matches).
        if (self.saved_pre_merge_new_coverage) |*cov| {
            if (cov.slot == slot) {
                const vlen = @min(cov.seen.len, validator_count);
                @memcpy(prev_new_seen[0..vlen], cov.seen[0..vlen]);
                const slen = @min(cov.has_subnet.len, committee_count);
                @memcpy(prev_new_has_subnet[0..slen], cov.has_subnet[0..slen]);
                // Fold into combined.
                for (prev_new_seen, 0..) |pn, i| if (pn) {
                    combined_seen[i] = true;
                };
                for (prev_new_has_subnet, 0..) |pn, i| if (pn) {
                    combined_has_subnet[i] = true;
                };
            }
        }

        // Fill late from current latest_new_aggregated_payloads (late arrivals after last merge).
        collectCoverageFromPayloads(
            &self.latest_new_aggregated_payloads,
            slot,
            committee_count_u32,
            late_seen,
            combined_seen,
            late_has_subnet,
            combined_has_subnet,
        );

        // Fill block from latest_block_aggregated_payloads.
        collectCoverageFromPayloads(
            &self.latest_block_aggregated_payloads,
            slot,
            committee_count_u32,
            block_seen,
            combined_seen,
            block_has_subnet,
            combined_has_subnet,
        );

        // Only emit a report if we have data in at least one section.
        var has_any = false;
        for (combined_has_subnet) |h| {
            if (h) {
                has_any = true;
                break;
            }
        }
        if (!has_any) return null;

        // Diff: validators in block but not in prev_new, and vice-versa.
        var block_not_prev_new: usize = 0;
        var prev_new_not_block: usize = 0;
        for (block_seen, prev_new_seen) |b, pn| {
            if (b and !pn) block_not_prev_new += 1;
            if (pn and !b) prev_new_not_block += 1;
        }

        recordAggregateCoverageMetrics("timely", prev_new_seen, prev_new_has_subnet, committee_count_u32);
        recordAggregateCoverageMetrics("late", late_seen, late_has_subnet, committee_count_u32);
        recordAggregateCoverageMetrics("block", block_seen, block_has_subnet, committee_count_u32);
        recordAggregateCoverageMetrics("combined", combined_seen, combined_has_subnet, committee_count_u32);
        zeam_metrics.metrics.lean_attestation_aggregate_coverage_diff_validators.set(.{ .direction = "block_only" }, @intCast(block_not_prev_new)) catch {};
        zeam_metrics.metrics.lean_attestation_aggregate_coverage_diff_validators.set(.{ .direction = "timely_only" }, @intCast(prev_new_not_block)) catch {};

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "last round attestation aggregate coverage: \n");
        try appendCoverageSection(allocator, &out, "timely", prev_new_seen, prev_new_has_subnet, validator_count, committee_count_u32);
        try out.appendSlice(allocator, " | \n");
        try appendCoverageSection(allocator, &out, "late", late_seen, late_has_subnet, validator_count, committee_count_u32);
        try out.appendSlice(allocator, " | \n");
        try appendCoverageSection(allocator, &out, "block", block_seen, block_has_subnet, validator_count, committee_count_u32);
        try out.appendSlice(allocator, " | \n");
        try appendCoverageSection(allocator, &out, "combined", combined_seen, combined_has_subnet, validator_count, committee_count_u32);

        const network_covered = countSeen(combined_seen);
        const network_pct = coveragePct(network_covered, validator_count);
        try appendFmt(allocator, &out, " | network={d}/{d}({d:.2}%)", .{ network_covered, validator_count, network_pct });
        try appendFmt(allocator, &out, " | diff(block-prev_new)=+{d}/-{d}", .{ block_not_prev_new, prev_new_not_block });

        return try out.toOwnedSlice(allocator);
    }

    /// Log subnet-wise coverage of the aggregation input set before the FFI runs.
    /// Called from aggregateImpl just before fork-choice aggregation.
    ///
    /// The aggregator's input is the **union** of two maps:
    ///   - `latest_new_aggregated_payloads`: cross-subnet aggregations received
    ///     from peers since the last accept-merge (reported as `new_payloads`).
    ///   - `attestation_signatures`: individual gossip signatures from this
    ///     node's subscribed subnets (reported as `gossip_sigs`).
    ///
    /// Earlier this function looked only at `latest_new_aggregated_payloads` and
    /// reported `coverage=none` whenever it was empty, even when dozens of
    /// individual gossip sigs were waiting on the local duty subnet (#899).
    /// Operators misread the "none" line as "we have no input"; the input was
    /// in fact a different map. Reporting both sections separately removes the
    /// ambiguity and surfaces "we have raw sigs from subnet 0 but no
    /// cross-subnet aggregations yet" — the common steady-state on a single-
    /// subnet aggregator.
    pub fn logNewPayloadsCoverageForAggregation(self: *Self, slot: types.Slot) void {
        const validator_count: usize = @intCast(self.config.genesis.numValidators());
        if (validator_count == 0) return;
        const committee_count_u32 = self.config.spec.attestation_committee_count;
        if (committee_count_u32 == 0) return;
        const committee_count: usize = @intCast(committee_count_u32);

        const new_seen = self.allocator.alloc(bool, validator_count) catch return;
        defer self.allocator.free(new_seen);
        const new_has_subnet = self.allocator.alloc(bool, committee_count) catch return;
        defer self.allocator.free(new_has_subnet);
        const gossip_seen = self.allocator.alloc(bool, validator_count) catch return;
        defer self.allocator.free(gossip_seen);
        const gossip_has_subnet = self.allocator.alloc(bool, committee_count) catch return;
        defer self.allocator.free(gossip_has_subnet);
        const dummy_seen = self.allocator.alloc(bool, validator_count) catch return;
        defer self.allocator.free(dummy_seen);
        const dummy_has = self.allocator.alloc(bool, committee_count) catch return;
        defer self.allocator.free(dummy_has);

        @memset(new_seen, false);
        @memset(new_has_subnet, false);
        @memset(gossip_seen, false);
        @memset(gossip_has_subnet, false);
        @memset(dummy_seen, false);
        @memset(dummy_has, false);

        self.signatures_mutex.lock();
        defer self.signatures_mutex.unlock();

        collectCoverageFromPayloads(
            &self.latest_new_aggregated_payloads,
            slot,
            committee_count_u32,
            new_seen,
            dummy_seen,
            new_has_subnet,
            dummy_has,
        );

        collectGossipSigCoverageForSlot(
            &self.attestation_signatures,
            slot,
            committee_count_u32,
            validator_count,
            gossip_seen,
            gossip_has_subnet,
        );

        var new_has_any = false;
        for (new_has_subnet) |h| if (h) {
            new_has_any = true;
            break;
        };
        var gossip_has_any = false;
        for (gossip_has_subnet) |h| if (h) {
            gossip_has_any = true;
            break;
        };

        recordAggregateCoverageMetrics("agg_start_new", new_seen, new_has_subnet, committee_count_u32);
        recordAggregateCoverageMetrics("agg_start_gossip", gossip_seen, gossip_has_subnet, committee_count_u32);

        if (!new_has_any and !gossip_has_any) {
            self.logger.info("agg start slot={d}: new_payloads=none gossip_sigs=none", .{slot});
            return;
        }

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        appendFmt(self.allocator, &out, "agg start slot={d}: ", .{slot}) catch return;
        if (new_has_any) {
            appendCoverageSection(self.allocator, &out, "new_payloads", new_seen, new_has_subnet, validator_count, committee_count_u32) catch return;
        } else {
            appendFmt(self.allocator, &out, "new_payloads=none", .{}) catch return;
        }
        appendFmt(self.allocator, &out, " | ", .{}) catch return;
        if (gossip_has_any) {
            appendCoverageSection(self.allocator, &out, "gossip_sigs", gossip_seen, gossip_has_subnet, validator_count, committee_count_u32) catch return;
        } else {
            appendFmt(self.allocator, &out, "gossip_sigs=none", .{}) catch return;
        }
        self.logger.info("{s}", .{out.items});
    }

    fn buildAggregateSourceAttribution(
        self: *Self,
        att_data: types.AttestationData,
        proof: types.TypeOneMultiSignature,
        source_payload_bits: *types.AggregationBits,
        source_gossip_bits: *types.AggregationBits,
    ) !void {
        const validator_count: usize = @intCast(self.config.genesis.numValidators());
        if (validator_count == 0) return;
        const committee_count = self.config.spec.attestation_committee_count;
        if (committee_count == 0) return;

        const payload_seen = try self.allocator.alloc(bool, validator_count);
        defer self.allocator.free(payload_seen);
        const gossip_seen = try self.allocator.alloc(bool, validator_count);
        defer self.allocator.free(gossip_seen);
        @memset(payload_seen, false);
        @memset(gossip_seen, false);

        collectSourceCoverageFromPayloadsForData(&self.latest_new_aggregated_payloads, att_data, committee_count, payload_seen, gossip_seen);
        collectSourceCoverageFromPayloadsForData(&self.latest_known_aggregated_payloads, att_data, committee_count, payload_seen, gossip_seen);
        collectCoverageFromSignaturesForData(&self.attestation_signatures, att_data, committee_count, gossip_seen);

        for (0..proof.participants.len()) |validator_index| {
            if (validator_index >= validator_count) continue;
            if (!(proof.participants.get(validator_index) catch false)) continue;

            if (payload_seen[validator_index]) {
                try types.aggregationBitsSet(source_payload_bits, validator_index, true);
            } else if (gossip_seen[validator_index]) {
                try types.aggregationBitsSet(source_gossip_bits, validator_index, true);
            } else {
                // Unknown source (for example, externally imported child payloads).
                // Count it as payload-originated rather than dropping coverage.
                try types.aggregationBitsSet(source_payload_bits, validator_index, true);
            }
        }
    }

    /// Aggregate attestation signatures using recursive child proofs.
    ///
    /// **#863 / #890 followup — snapshot-then-release.** The XMSS
    /// aggregate-proof FFI inside `computeAggregatedSignatures` runs
    /// for ~18 s per call on devnet aggregators (see
    /// `lean_committee_signatures_aggregation_time_seconds`). The
    /// previous shape held `signatures_mutex` for that whole window,
    /// so libxev's `chain.onInterval` → `tickIntervalUnlocked` →
    /// `acceptNewAttestationsUnlocked` (which also takes
    /// `signatures_mutex`) blocked at intervals 0/3/4 every slot an
    /// aggregation was in flight. The slot-driver watchdog fired
    /// every i=4 tick during aggregation as a result.
    ///
    /// This shape splits the body into three phases:
    ///
    ///   1. **Snapshot** (signatures_mutex held briefly, ms-scale):
    ///      deep-clone `attestation_signatures`, `latest_new_aggregated_payloads`,
    ///      `latest_known_aggregated_payloads` into owned local copies.
    ///      Release.
    ///   2. **Compute** (no lock held, ~18 s):
    ///      run `computeAggregatedSignatures` and per-result SSZ clones
    ///      against the owned snapshot. While this runs, `addSignature`
    ///      / `storeAggregatedPayload` / `acceptNewAttestationsUnlocked`
    ///      / `pruneStaleAttestationData` are free to mutate the live
    ///      maps.
    ///   3. **Commit** (signatures_mutex held briefly, ms-scale):
    ///      MERGE per-att_data new aggregations into
    ///      `latest_new_aggregated_payloads` (do NOT REPLACE — gossip-
    ///      sourced aggregations from other subnets that arrived during
    ///      phase 2 must survive). Per-validator remove from
    ///      `attestation_signatures` for the (att_data, validator_id)
    ///      pairs that existed at snapshot time (entries added during
    ///      phase 2 stay so the next aggregator pass can consume them).
    ///
    /// `submitAggregateOnInterval` already gates concurrent
    /// `aggregate()` calls via `aggregate_group.concurrent`
    /// (concurrent_limit=1), so two aggregations cannot race here.
    fn aggregateUnlocked(self: *Self, state_opt: ?*const types.BeamState, slot_filter: ?[]const types.Slot) ![]types.SignedAggregatedAttestation {
        const state = state_opt orelse return try self.allocator.alloc(types.SignedAggregatedAttestation, 0);
        const agg_timer = zeam_metrics.lean_committee_signatures_aggregation_time_seconds.start();
        defer _ = agg_timer.observe();

        // ─── Phase 1: snapshot ──────────────────────────────────────
        // Deep-clone the three input maps under signatures_mutex so
        // computeAggregatedSignatures (phase 2) can run on owned data
        // without holding the lock. Cost is bounded by total entry
        // count: SignaturesMap is POD (StoredSignature is 8B + SIGBYTES);
        // AggregatedPayloadsMap entries each sszClone an
        // AggregatedSignatureProof (Rust-allocated XMSS handle, refcount
        // bump via FFI). Per-entry clone is sub-ms; total snapshot
        // typically O(10 ms) on a healthy aggregator.
        const snapshot_start_ns = zeam_utils.monotonicTimestampNs();
        var snap = try AggregateSnapshot.takeUnderLock(self);
        observeAggregateBuildPhase("snapshot", snapshot_start_ns);
        defer snap.deinit(self.allocator);

        // ─── Phase 2: compute (no lock held) ────────────────────────
        var agg = try types.AggregatedAttestationsResult.init(self.allocator);
        var agg_att_cleanup = true;
        var agg_sig_cleanup = true;
        errdefer if (agg_att_cleanup) {
            for (agg.attestations.slice()) |*att| att.deinit();
            agg.attestations.deinit();
        };
        errdefer if (agg_sig_cleanup) {
            for (agg.attestation_signatures.slice()) |*sig| sig.deinit();
            agg.attestation_signatures.deinit();
        };

        // Aggregator-only policy filter: drop `att_data` entries from the
        // owned snapshot whose only input is a single (or sub-threshold)
        // local gossip sig and which have no peer payload to fold into.
        // This MUST live here in the aggregator wrapper, NOT inside
        // `computeAggregatedSignatures`: the same FFI function is the
        // primitive a future block proposer would use to aggregate the
        // exact `att_data` set it chose to include in a block, and a
        // proposer must aggregate every chosen `att_data` (blocks carry
        // aggregated proofs, not raw sigs) — even a 1-validator one. By
        // filtering the snapshot before the FFI runs, the function
        // remains spec-pure (aggregate whatever you are given) and the
        // policy is opt-in per call site.
        pruneTrivialFromAggregateSnapshot(
            self.allocator,
            &snap,
            self.min_aggregation_inputs,
            self.logger,
        );

        const compute_start_ns = zeam_utils.monotonicTimestampNs();
        try agg.computeAggregatedSignatures(
            &state.validators,
            &snap.signatures,
            &snap.new_payloads,
            &snap.known_payloads,
            slot_filter,
        );
        observeAggregateBuildPhase("compute_ffi", compute_start_ns);

        // Build the per-att_data map of fresh aggregations and the
        // result slice while no lock is held. SSZ-clone per proof
        // twice (once for our internal map, once for the caller's
        // slice) — both clones are independent Rust handles.
        //
        // `defer` (not `errdefer`) — on the success path the lock
        // block below transfers ownership of every
        // `StoredAggregatedPayload` into `self.latest_new_aggregated_payloads`
        // and resets each value list to `.empty`. The deferred
        // `deinitAggregatedPayloadsMap` then walks the (now-empty)
        // value lists, frees their zero-capacity buffers, and frees
        // the outer hashmap. On any error path before the transfer
        // completes, any retained `AggregatedSignatureProof` is
        // released the same way.
        var new_payloads_local = AggregatedPayloadsMap.init(self.allocator);
        defer deinitAggregatedPayloadsMap(self.allocator, &new_payloads_local);

        var results: std.ArrayList(types.SignedAggregatedAttestation) = .empty;
        errdefer {
            for (results.items) |*signed| signed.deinit();
            results.deinit(self.allocator);
        }

        var aggregated_att_data_keys: std.ArrayList(types.AttestationData) = .empty;
        defer aggregated_att_data_keys.deinit(self.allocator);

        {
            const agg_attestations = agg.attestations.constSlice();
            const agg_signatures = agg.attestation_signatures.constSlice();

            for (agg_attestations, 0..) |agg_att, index| {
                const proof = agg_signatures[index];

                try aggregated_att_data_keys.append(self.allocator, agg_att.data);

                // Store proof into new payloads map, preserving source attribution
                // so block proposal logs can split selected coverage into child-payload
                // vs raw-gossip origins after this aggregate is promoted to known.
                const gop = try new_payloads_local.getOrPut(agg_att.data);
                if (!gop.found_existing) gop.value_ptr.* = .empty;

                var source_payload_bits = try types.AggregationBits.init(self.allocator);
                var source_payload_bits_owned = true;
                errdefer if (source_payload_bits_owned) source_payload_bits.deinit();
                var source_gossip_bits = try types.AggregationBits.init(self.allocator);
                var source_gossip_bits_owned = true;
                errdefer if (source_gossip_bits_owned) source_gossip_bits.deinit();
                try self.buildAggregateSourceAttribution(agg_att.data, proof, &source_payload_bits, &source_gossip_bits);

                var cloned_proof: types.TypeOneMultiSignature = undefined;
                try types.sszClone(self.allocator, types.TypeOneMultiSignature, proof, &cloned_proof);
                errdefer cloned_proof.deinit();
                try gop.value_ptr.append(self.allocator, .{
                    .slot = agg_att.data.slot,
                    .proof = cloned_proof,
                    .source_payload_participants = source_payload_bits,
                    .source_gossip_participants = source_gossip_bits,
                });
                source_payload_bits_owned = false;
                source_gossip_bits_owned = false;

                var output_proof: types.TypeOneMultiSignature = undefined;
                try types.sszClone(self.allocator, types.TypeOneMultiSignature, proof, &output_proof);
                errdefer output_proof.deinit();
                try results.append(self.allocator, .{
                    .data = agg_att.data,
                    .proof = output_proof,
                });
            }
        }

        // ─── Phase 3: commit (signatures_mutex held briefly) ────────
        var new_payloads_count: usize = 0;
        var gossip_sigs_count: usize = 0;
        const commit_start_ns = zeam_utils.monotonicTimestampNs();
        {
            self.signatures_mutex.lock();
            defer self.signatures_mutex.unlock();

            // MERGE (NOT replace). The previous shape did
            //   deinitAggregatedPayloadsMap(allocator, &self.latest_new_aggregated_payloads);
            //   self.latest_new_aggregated_payloads = new_payloads_local;
            // which was safe because the lock was held across compute
            // so nothing could append in between. With phase 2
            // unlocked, gossip-sourced aggregations (other subnets'
            // `storeAggregatedPayload(is_from_block=false)`) and
            // accept's clear/migrate can mutate `latest_new_*` while
            // we work. Replace would clobber those gossip
            // aggregations. Merge appends ours instead; greedy proof
            // selection in `getProposalAttestations` already
            // de-duplicates overlapping proofs across the resulting
            // list so the only cost of merge is a slightly larger
            // payload list per att_data (bounded by
            // `acceptNewAttestationsUnlocked`'s clear-on-i=0/i=4
            // tick).
            var local_iter = new_payloads_local.iterator();
            while (local_iter.next()) |entry| {
                const att_data = entry.key_ptr.*;
                const list = entry.value_ptr;

                const gop = try self.latest_new_aggregated_payloads.getOrPut(att_data);
                if (!gop.found_existing) gop.value_ptr.* = .empty;
                try gop.value_ptr.appendSlice(self.allocator, list.items);

                // Ownership of every StoredAggregatedPayload moved
                // into self.latest_new_aggregated_payloads. Free the
                // local list buffer (no proofs to deinit — they all
                // moved) and reset to `.empty` so the deferred
                // `deinitAggregatedPayloadsMap` is a no-op walk over
                // empty lists.
                list.deinit(self.allocator);
                list.* = .empty;
            }

            // Per-validator remove from live `attestation_signatures`
            // for every (att_data, vid) pair that EXISTED IN THE
            // SNAPSHOT for an aggregated key. Snapshot vids are the
            // upper bound of what compute could have consumed (some
            // were skipped because already covered by children, but
            // those are redundant in the live map too — safe to drop).
            // Vids added by `addSignature` during phase 2 are NOT in
            // the snapshot, so they survive and feed the next
            // aggregate cycle.
            for (aggregated_att_data_keys.items) |att_data| {
                const snap_inner_kv = snap.signatures.fetchRemove(att_data) orelse continue;
                var snap_inner = snap_inner_kv.value;
                defer snap_inner.deinit();
                if (self.attestation_signatures.getPtr(att_data)) |live_inner| {
                    var snap_vid_it = snap_inner.iterator();
                    while (snap_vid_it.next()) |vid_entry| {
                        _ = live_inner.remove(vid_entry.key_ptr.*);
                    }
                    if (live_inner.count() == 0) {
                        self.attestation_signatures.removeAndDeinit(att_data);
                    }
                }
            }

            new_payloads_count = self.latest_new_aggregated_payloads.count();
            gossip_sigs_count = self.attestation_signatures.count();
        }
        observeAggregateBuildPhase("commit", commit_start_ns);

        // Phase 2 cleanup: free the AggregatedAttestationsResult
        // local now that ownership of every cloned proof has either
        // moved into self.latest_new_aggregated_payloads (via the
        // merge above) or into `results` (returned to caller).
        agg_att_cleanup = false;
        agg_sig_cleanup = false;
        for (agg.attestations.slice()) |*att| att.deinit();
        agg.attestations.deinit();
        for (agg.attestation_signatures.slice()) |*sig| sig.deinit();
        agg.attestation_signatures.deinit();

        zeam_metrics.metrics.lean_latest_new_aggregated_payloads.set(@intCast(new_payloads_count));
        zeam_metrics.metrics.lean_gossip_signatures.set(@intCast(gossip_sigs_count));

        return results.toOwnedSlice(self.allocator);
    }

    /// Produce aggregations only for the caller-supplied attestation slots.
    ///
    /// The aggregate worker is scheduled with `aggregate_group.concurrent`
    /// (concurrent_limit=1), so a busy worker can skip an interval. Callers should
    /// pass a small backfill window, e.g. `{current_slot - 1, current_slot}`, to
    /// recover late or skipped-slot attestations without walking every stale/future
    /// `AttestationData` key retained in the maps.
    pub fn aggregateForSlots(self: *Self, state_opt: ?*const types.BeamState, slots: []const types.Slot) ![]types.SignedAggregatedAttestation {
        return self.aggregateUnlocked(state_opt, slots);
    }

    /// Convenience wrapper for tests or callers that intentionally want strict
    /// single-slot aggregation. Production should prefer `aggregateForSlots`.
    pub fn aggregateForSlot(self: *Self, state_opt: ?*const types.BeamState, slot: types.Slot) ![]types.SignedAggregatedAttestation {
        return self.aggregateForSlots(state_opt, &.{slot});
    }

    /// Remove attestation data that can no longer influence fork choice.
    ///
    /// An attestation becomes stale when its target checkpoint falls at or before
    /// the finalized slot. Such attestations cannot affect chain selection since
    /// the target is already finalized.
    ///
    /// Pruning removes all attestation-related data:
    /// - Attestation data entries
    /// - Gossip signatures
    /// - Pending aggregated payloads
    /// - Processed aggregated payloads
    pub fn pruneStaleAttestationData(self: *Self, finalized_slot: types.Slot) !void {
        self.signatures_mutex.lock();
        defer self.signatures_mutex.unlock();

        // Collect stale AttestationData keys from attestation_signatures (target.slot <= finalized)
        var att_sig_keys_to_remove: std.ArrayList(types.AttestationData) = .empty;
        defer att_sig_keys_to_remove.deinit(self.allocator);

        var att_sig_it = self.attestation_signatures.iterator();
        while (att_sig_it.next()) |entry| {
            if (entry.key_ptr.target.slot <= finalized_slot) {
                try att_sig_keys_to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (att_sig_keys_to_remove.items) |data| {
            self.attestation_signatures.removeAndDeinit(data);
        }

        const removed_known = try prunePayloadMapBySlot(self.allocator, &self.latest_known_aggregated_payloads, finalized_slot);
        const removed_new = try prunePayloadMapBySlot(self.allocator, &self.latest_new_aggregated_payloads, finalized_slot);

        self.logger.debug(
            "pruned stale attestation data: gossip={d} payloads_known={d} payloads_new={d} finalized_slot={d}",
            .{
                att_sig_keys_to_remove.items.len,
                removed_known,
                removed_new,
                finalized_slot,
            },
        );
    }

    fn prunePayloadMapBySlot(
        allocator: Allocator,
        payloads: *AggregatedPayloadsMap,
        finalized_slot: types.Slot,
    ) !usize {
        var keys_to_remove: std.ArrayList(types.AttestationData) = .empty;
        defer keys_to_remove.deinit(allocator);

        var removed_total: usize = 0;
        var it = payloads.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.target.slot > finalized_slot) continue;

            removed_total += entry.value_ptr.items.len;
            try keys_to_remove.append(allocator, entry.key_ptr.*);
        }

        for (keys_to_remove.items) |data| {
            if (payloads.fetchRemove(data)) |kv| {
                var mutable_val = kv.value;
                deinitAggregatedPayloadsList(allocator, &mutable_val);
            }
        }
        return removed_total;
    }

    // we process state outside forkchoice onblock to parallize verifications and just use the post state here
    // Internal unlocked version - assumes caller holds lock
    fn onBlockUnlocked(self: *Self, block: types.BeamBlock, state: *const types.BeamState, opts: OnBlockOpts) !ProtoBlock {
        const parent_root = block.parent_root;
        const slot = block.slot;

        const parent_block_or_null = self.getBlockUnlocked(parent_root);
        if (parent_block_or_null) |parent_block| {
            // we will use parent block later as per the finalization gadget
            _ = parent_block;

            // Block admission only requires a known parent and a slot above
            // the finalized boundary; STF and signature verification are the
            // gating layers.
            if (slot < self.fcStore.latest_finalized.slot) {
                return ForkChoiceError.PreFinalizedSlot;
            }

            // Per leanSpec store.process_block: a block may include at most
            // MAX_ATTESTATIONS_DATA (8) distinct AttestationData entries, and
            // each distinct entry must appear exactly once. Enforce this before
            // registering the block in protoArray so rejected blocks leave no
            // residue in fork choice state.
            try validateAttestationDataLimits(self.allocator, block.body.attestations.constSlice());

            // onBlock is a pure store operation aligned with leanSpec's
            // store.on_block: any block whose parent is in protoArray is stored,
            // and head selection naturally ignores forks that do not descend
            // from the finalized root (get_head walks best descendants from
            // latest_justified). The gossip-level DoS defense against forks
            // branching off pre-finalization ancestors lives in
            // chain.validateBlock, not here.

            const justified = state.latest_justified;
            const finalized = state.latest_finalized;
            const prev_justified_slot = self.fcStore.latest_justified.slot;
            self.fcStore.update(justified, finalized);
            // Transition from initing to ready once we observe a real justified checkpoint
            // that is strictly newer than the anchor (i.e., actual chain progress has been seen).
            if (self.status == .initing and self.fcStore.latest_justified.slot > prev_justified_slot) {
                self.status = .ready;
                self.logger.info("[forkchoice] status=ready: first justified checkpoint observed slot={d} root={x} — validator duties now enabled", .{ self.fcStore.latest_justified.slot, &self.fcStore.latest_justified.root });
            }

            const block_root: [32]u8 = if (opts.blockRoot) |r| r else r: {
                var cblock_root: [32]u8 = undefined;
                try zeam_utils.hashTreeRoot(types.BeamBlock, block, &cblock_root, self.allocator);
                break :r cblock_root;
            };
            if (opts.blockRoot != null) {
                // Slice (e) of #803 — see metrics field doc on
                // `lean_block_root_compute_skipped_total`.
                zeam_metrics.metrics.lean_block_root_compute_skipped_total.incr(.{ .site = "forkchoice.onBlock" }) catch {};

                // PR #842 review #2: trust-but-verify the
                // caller-supplied root against a fresh hash in
                // debug + ReleaseSafe builds. Cheap (debug-only)
                // safety net for future call sites that thread a
                // stale or wrong root through
                // `OnBlockOpts.blockRoot`. The forkchoice's
                // protoArray indexes by this root and the spec
                // guarantees uniqueness via SSZ collision-
                // resistance; if a caller fabricates a root, we'd
                // silently corrupt the protoArray. Per-call cost is
                // one `hashTreeRoot(BeamBlock, ...)` and is paid
                // ONLY in `Debug` / `ReleaseSafe`; `ReleaseFast` /
                // `ReleaseSmall` skip the block entirely so
                // production keeps the slice-(e) win.
                if (std.debug.runtime_safety) verify: {
                    var verify_root: [32]u8 = undefined;
                    zeam_utils.hashTreeRoot(types.BeamBlock, block, &verify_root, self.allocator) catch |err| {
                        // Re-hash failure here is itself a bug, but
                        // we don't want a forkchoice panic on an
                        // OOM during the verification step — log
                        // and skip so the caller-supplied root is
                        // still used.
                        self.logger.warn(
                            "forkchoice.onBlock: blockRoot verification re-hash failed: {any}",
                            .{err},
                        );
                        break :verify;
                    };
                    if (!std.mem.eql(u8, &block_root, &verify_root)) {
                        std.debug.panic(
                            "forkchoice.onBlock: caller-supplied blockRoot=0x{x} does NOT match recomputed=0x{x} for block slot={d} — protoArray would be silently corrupted; call site bug",
                            .{ &block_root, &verify_root, slot },
                        );
                    }
                }
            }
            const is_timely = self.isBlockTimely(opts.blockDelayMs);

            const proto_block = ProtoBlock{
                .slot = slot,
                .proposer_index = block.proposer_index,
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

    // Internal unlocked version - assumes caller holds lock
    fn confirmBlockUnlocked(self: *Self, blockRoot: types.Root) !void {
        if (self.protoArray.indices.get(blockRoot)) |block_idx| {
            self.protoArray.nodes.items[block_idx].confirmed = true;
        } else {
            return ForkChoiceError.InvalidForkchoiceBlock;
        }
    }

    // Internal unlocked version - assumes caller holds lock
    fn getBlockUnlocked(self: *Self, blockRoot: types.Root) ?ProtoBlock {
        const nodeOrNull = self.protoArray.getNode(blockRoot);
        if (nodeOrNull) |node| {
            // TODO cast doesn't seem to be working find resolution
            // const block = utils.Cast(ProtoBlock, node);
            const block = ProtoBlock{
                .slot = node.slot,
                .proposer_index = node.proposer_index,
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

    // Internal unlocked version - assumes caller holds lock
    fn hasBlockUnlocked(self: *Self, blockRoot: types.Root) bool {
        return self.protoArray.indices.contains(blockRoot);
    }

    //  PUBLIC API - LOCK AT BOUNDARY
    // These methods acquire locks and delegate to unlocked helpers

    pub fn updateHead(self: *Self) !ProtoBlock {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.updateHeadUnlocked();
    }

    pub fn onBlock(self: *Self, block: types.BeamBlock, state: *const types.BeamState, opts: OnBlockOpts) !ProtoBlock {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.onBlockUnlocked(block, state, opts);
    }

    pub fn onInterval(self: *Self, time_intervals: usize, has_proposal: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.onIntervalUnlocked(time_intervals, has_proposal);
    }

    pub fn onAttestation(self: *Self, attestation: types.Attestation, is_from_block: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.onAttestationUnlocked(attestation, is_from_block);
    }

    pub fn onSignedAttestation(self: *Self, signed_attestation: types.SignedAttestation) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.onSignedAttestationUnlocked(signed_attestation);
    }

    pub fn updateSafeTarget(self: *Self) !ProtoBlock {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.updateSafeTargetUnlocked();
    }

    //  READ-ONLY API - SHARED LOCK

    pub fn getProposalAttestations(
        self: *Self,
        pre_state: *const types.BeamState,
        slot: types.Slot,
        proposer_index: types.ValidatorIndex,
        parent_root: [32]u8,
    ) !ProposalAttestationsResult {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.getProposalAttestationsUnlocked(pre_state, slot, proposer_index, parent_root);
    }

    pub fn getAttestationTarget(self: *Self) !types.Checkpoint {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.getAttestationTargetUnlocked();
    }

    pub fn hasBlock(self: *Self, blockRoot: types.Root) bool {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.hasBlockUnlocked(blockRoot);
    }

    /// Slice (d) of #803: batch presence check.
    ///
    /// Snapshots `hasBlock` for every root in `roots` under a single
    /// shared-lock acquisition, writing results into `out` (which the
    /// caller pre-allocates with `out.len == roots.len`). The batched
    /// shape lets the producer (`BeamNode.fetchBlockByRoots`) trade N
    /// shared-lock acquisitions + N hashmap lookups for 1 + N — the
    /// hashmap lookup is unchanged but the lock-acquire/release pair
    /// (and the ConcurrencyKit memory fence inside it) collapses to
    /// one. Under heavy gossip-fanout the lock-acquire dominates the
    /// hashmap lookup, so this is the call we want for every dedup
    /// pass that operates on a list of roots.
    ///
    /// Returns `error.LengthMismatch` if `roots.len != out.len` so
    /// the caller cannot accidentally read garbage past the end of
    /// `out`.
    pub fn hasBlocksBatch(
        self: *Self,
        roots: []const types.Root,
        out: []bool,
    ) error{LengthMismatch}!void {
        if (roots.len != out.len) return error.LengthMismatch;
        if (roots.len == 0) return;
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        for (roots, 0..) |root, i| {
            out[i] = self.hasBlockUnlocked(root);
        }
    }

    pub fn getBlock(self: *Self, blockRoot: types.Root) ?ProtoBlock {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.getBlockUnlocked(blockRoot);
    }

    pub fn getCanonicalView(self: *Self, canonical_view: *std.AutoHashMap(types.Root, void), targetAnchorRoot: types.Root, prevAnchorRootOrNull: ?types.Root) !void {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.getCanonicalViewUnlocked(canonical_view, targetAnchorRoot, prevAnchorRootOrNull);
    }

    /// Builds canonical view and analysis under a single shared lock for snapshot consistency.
    pub fn getCanonicalViewAndAnalysis(self: *Self, canonical_view: *std.AutoHashMap(types.Root, void), targetAnchorRoot: types.Root, prevAnchorRootOrNull: ?types.Root) ![3][]types.Root {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        try self.getCanonicalViewUnlocked(canonical_view, targetAnchorRoot, prevAnchorRootOrNull);
        return self.getCanonicalityAnalysisUnlocked(targetAnchorRoot, prevAnchorRootOrNull, canonical_view);
    }

    pub fn getCanonicalityAnalysis(self: *Self, targetAnchorRoot: types.Root, prevAnchorRootOrNull: ?types.Root, canonicalViewOrNull: ?*std.AutoHashMap(types.Root, void)) ![3][]types.Root {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.getCanonicalityAnalysisUnlocked(targetAnchorRoot, prevAnchorRootOrNull, canonicalViewOrNull);
    }

    pub fn rebase(self: *Self, targetAnchorRoot: types.Root, canonicalViewOrNull: ?*std.AutoHashMap(types.Root, void)) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.rebaseUnlocked(targetAnchorRoot, canonicalViewOrNull);
    }

    pub fn getCanonicalAncestorAtDepth(self: *Self, min_depth: usize) !ProtoBlock {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.getCanonicalAncestorAtDepthUnlocked(min_depth);
    }

    pub fn confirmBlock(self: *Self, blockRoot: types.Root) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.confirmBlockUnlocked(blockRoot);
    }

    pub fn computeDeltas(self: *Self, from_known: bool) ![]isize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.computeDeltasUnlocked(from_known);
    }

    pub fn applyDeltas(self: *Self, deltas: []isize, cutoff_weight: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.protoArray.applyDeltasUnlocked(deltas, cutoff_weight);
    }

    pub fn acceptNewAttestations(self: *Self) !ProtoBlock {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.acceptNewAttestationsUnlocked();
    }

    //  SAFE GETTERS FOR SHARED STATE
    // These provide thread-safe access to internal state

    /// Get a copy of the current head block
    pub fn getHead(self: *Self) ProtoBlock {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.head;
    }

    /// Get the current safe target block (thread-safe)
    pub fn getSafeTarget(self: *Self) ProtoBlock {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.safeTarget;
    }

    /// Get the latest justified checkpoint
    pub fn getLatestJustified(self: *Self) types.Checkpoint {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.fcStore.latest_justified;
    }

    /// Get the latest finalized checkpoint
    pub fn getLatestFinalized(self: *Self) types.Checkpoint {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.fcStore.latest_finalized;
    }

    /// Returns true when the forkchoice has observed a real justified checkpoint via block
    /// processing and is ready for validator duties (block production, attestation).
    /// For genesis init this is immediately true; for checkpoint-sync it becomes true
    /// after the first onBlock call that advances latest_justified.
    pub fn isReady(self: *Self) bool {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.status == .ready;
    }

    /// Get the current time in slots
    pub fn getCurrentSlot(self: *Self) types.Slot {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.fcStore.slot_clock.timeSlots.load(.monotonic);
    }

    /// Check if a block exists and get its slot (thread-safe)
    pub fn getBlockSlot(self: *Self, blockRoot: types.Root) ?types.Slot {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        const idx = self.protoArray.indices.get(blockRoot) orelse return null;
        return self.protoArray.nodes.items[idx].slot;
    }

    /// Get a ProtoNode by root (returns a copy)
    pub fn getProtoNode(self: *Self, blockRoot: types.Root) ?ProtoNode {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        const idx = self.protoArray.indices.get(blockRoot) orelse return null;
        return self.protoArray.nodes.items[idx];
    }

    /// Get a ProtoNode's index in the underlying nodes array. Callers use
    /// this to measure how many nodes precede a given block (e.g. to gate
    /// proto-array rebase on a grace-window threshold).
    pub fn getProtoNodeIndex(self: *Self, blockRoot: types.Root) ?usize {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.protoArray.indices.get(blockRoot);
    }

    /// Get the current number of nodes in the forkchoice tree
    pub fn getNodeCount(self: *Self) usize {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        return self.protoArray.nodes.items.len;
    }
};

pub const ForkChoiceError = error{
    NotImplemented,
    UnknownParent,
    InvalidFutureAttestation,
    InvalidOnChainAttestation,
    PreFinalizedSlot,
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
    InvalidSafeTargetCompute,
    DuplicateAttestationData,
    TooManyAttestationData,
};

fn initTestThreadPool() !*ThreadPool {
    return @import("./testing.zig").initTestThreadPool(std.testing.allocator);
}

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_attestation_pubkeys instead of num_validators
test "forkchoice block tree" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Use genMockChain with null to generate default genesis with pubkeys
    const mock_chain = try stf.genMockChain(allocator, 2, null);

    // Create chain config from mock chain genesis
    const spec_name = try allocator.dupe(u8, "beamdev");
    const fork_digest = try allocator.dupe(u8, "12345678");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 8,
        },
    };
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.forkchoice);
    const test_thread_pool = try initTestThreadPool();
    defer test_thread_pool.deinit();
    var fork_choice = try ForkChoice.init(allocator, .{
        .config = chain_config,
        .anchorState = &beam_state,
        .logger = module_logger,
        .thread_pool = test_thread_pool,
    });

    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.latest_finalized.root, &mock_chain.blockRoots[0]));
    try std.testing.expect(fork_choice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.latest_finalized.root, &fork_choice.protoArray.nodes.items[0].blockRoot));
    try std.testing.expect(std.mem.eql(u8, mock_chain.blocks[0].block.state_root[0..], &fork_choice.protoArray.nodes.items[0].stateRoot));
    try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[0], &fork_choice.protoArray.nodes.items[0].blockRoot));

    for (1..mock_chain.blocks.len) |i| {
        // get the block post state
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.block;
        try stf.apply_transition(allocator, &beam_state, block, .{ .logger = module_logger });

        // onBlock only requires a known parent and a non-pre-finalized slot.
        try fork_choice.onInterval(block.slot * constants.INTERVALS_PER_SLOT, false);
        _ = try fork_choice.onBlock(block, &beam_state, .{ .currentSlot = block.slot, .blockDelayMs = 0, .confirmed = true });
        try std.testing.expect(fork_choice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &fork_choice.protoArray.nodes.items[i].blockRoot));

        const searched_idx = fork_choice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);
    }
}

test "hasBlocksBatch (slice (d) of #803): empty + length-mismatch + presence semantics" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 3, null);
    const spec_name = try allocator.dupe(u8, "beamdev");
    const fork_digest = try allocator.dupe(u8, "12345678");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 8,
        },
    };
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.forkchoice);
    const test_thread_pool = try initTestThreadPool();
    defer test_thread_pool.deinit();
    var fork_choice = try ForkChoice.init(allocator, .{
        .config = chain_config,
        .anchorState = &beam_state,
        .logger = module_logger,
        .thread_pool = test_thread_pool,
    });

    // 1. Empty input is a no-op (does not panic / does not deadlock).
    var empty_buf: [0]bool = .{};
    try fork_choice.hasBlocksBatch(&[_]types.Root{}, &empty_buf);

    // 2. Length mismatch is reported as an error rather than a UB read.
    var bad_out: [1]bool = .{false};
    try std.testing.expectError(
        error.LengthMismatch,
        fork_choice.hasBlocksBatch(&[_]types.Root{ mock_chain.blockRoots[0], mock_chain.blockRoots[0] }, &bad_out),
    );

    // 3. Anchor block (genesis) is present; a synthetic root is not.
    //    Same shared lock acquisition snapshots both answers.
    const synthetic = std.mem.zeroes(types.Root);
    var roots: [3]types.Root = .{ mock_chain.blockRoots[0], synthetic, mock_chain.blockRoots[0] };
    var present: [3]bool = .{ false, true, false };
    try fork_choice.hasBlocksBatch(&roots, &present);
    try std.testing.expect(present[0]);
    try std.testing.expect(!present[1]);
    try std.testing.expect(present[2]);

    // 4. After ingesting block[1], `hasBlocksBatch` reflects the new state
    //    in the same call shape — confirms the shared-lock snapshot is
    //    re-taken on every call (not cached across).
    const block1 = mock_chain.blocks[1].block;
    try stf.apply_transition(allocator, &beam_state, block1, .{ .logger = module_logger });
    try fork_choice.onInterval(block1.slot * constants.INTERVALS_PER_SLOT, false);
    _ = try fork_choice.onBlock(block1, &beam_state, .{ .currentSlot = block1.slot, .blockDelayMs = 0, .confirmed = true });

    var roots2: [2]types.Root = .{ mock_chain.blockRoots[1], synthetic };
    var present2: [2]bool = .{ false, true };
    try fork_choice.hasBlocksBatch(&roots2, &present2);
    try std.testing.expect(present2[0]);
    try std.testing.expect(!present2[1]);
}

test "aggregate prunes attestation signatures" {
    const allocator = std.testing.allocator;
    const validator_count: usize = 4;
    const num_blocks: usize = 1;

    var key_manager = try keymanager.getTestKeyManager(allocator, validator_count, num_blocks);
    defer key_manager.deinit();

    const all_pubkeys = try key_manager.getAllPubkeys(allocator, validator_count);
    defer allocator.free(all_pubkeys.attestation_pubkeys);
    defer allocator.free(all_pubkeys.proposal_pubkeys);

    const genesis_spec = types.GenesisSpec{
        .genesis_time = 1234,
        .validator_attestation_pubkeys = all_pubkeys.attestation_pubkeys,
        .validator_proposal_pubkeys = all_pubkeys.proposal_pubkeys,
    };

    var mock_chain = try stf.genMockChain(allocator, num_blocks, genesis_spec);
    defer mock_chain.deinit(allocator);
    defer mock_chain.genesis_state.validators.deinit();
    defer mock_chain.genesis_state.historical_block_hashes.deinit();
    defer mock_chain.genesis_state.justified_slots.deinit();
    defer mock_chain.genesis_state.justifications_roots.deinit();
    defer mock_chain.genesis_state.justifications_validators.deinit();

    const spec_name = try allocator.dupe(u8, "beamdev");
    const fork_digest = try allocator.dupe(u8, "12345678");
    defer allocator.free(spec_name);
    defer allocator.free(fork_digest);
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 8,
        },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const test_thread_pool = try initTestThreadPool();
    defer test_thread_pool.deinit();
    var fork_choice = try ForkChoice.init(allocator, .{
        .config = chain_config,
        .anchorState = &mock_chain.genesis_state,
        .logger = zeam_logger_config.logger(.forkchoice),
        .thread_pool = test_thread_pool,
    });
    defer fork_choice.deinit();

    const attestation_data = types.AttestationData{
        .slot = 0,
        .head = .{
            .root = fork_choice.head.blockRoot,
            .slot = 0,
        },
        .target = .{
            .root = fork_choice.head.blockRoot,
            .slot = 0,
        },
        .source = .{
            .root = fork_choice.head.blockRoot,
            .slot = 0,
        },
    };
    // Two signatures from distinct validators on the same AttestationData
    // exercise the aggregation path and the post-commit pruning this test
    // asserts.
    inline for ([_]u32{ 0, 1 }) |validator_id| {
        const attestation = types.Attestation{
            .validator_id = validator_id,
            .data = attestation_data,
        };
        const signature = try key_manager.signAttestation(&attestation, allocator);
        try fork_choice.onSignedAttestation(.{
            .validator_id = validator_id,
            .message = attestation_data,
            .signature = signature,
        });
    }

    const aggregations = try fork_choice.aggregateForSlots(&mock_chain.genesis_state, &.{0});
    defer {
        for (aggregations) |*signed_aggregation| {
            signed_aggregation.deinit();
        }
        allocator.free(aggregations);
    }

    try std.testing.expectEqual(@as(usize, 1), aggregations.len);
    try std.testing.expectEqual(@as(usize, 0), fork_choice.attestation_signatures.count());
    try std.testing.expect(fork_choice.latest_new_aggregated_payloads.get(attestation_data) != null);
}

test "aggregate (#890): does not acquire forkchoice main mutex" {
    // Regression for the slot-driver stall on aggregator devnet nodes:
    // before this PR, `forkChoice.aggregate` took `mutex.lock()` for the
    // entire ~70s XMSS aggregate FFI, blocking libxev's `chain.onInterval`
    // (which also acquires the same mutex) and the chain-worker thread
    // (block import / per-attestation tracker updates).
    //
    // The contract going forward: `aggregate` MUST NOT acquire the
    // forkchoice main mutex. Internal coordination is via
    // `signatures_mutex`, which is the only lock the heavy aggregation
    // body needs. We assert the contract by holding the main mutex
    // EXCLUSIVE on the test thread and observing that the aggregator
    // thread completes without deadlocking. If a future refactor
    // re-introduces `mutex.lock()` (or any acquisition that the
    // aggregator must wait for), this test will hang at `thread.join()`
    // and the CI watchdog will fail it.
    const allocator = std.testing.allocator;
    const validator_count: usize = 4;
    const num_blocks: usize = 1;

    var key_manager = try keymanager.getTestKeyManager(allocator, validator_count, num_blocks);
    defer key_manager.deinit();

    const all_pubkeys = try key_manager.getAllPubkeys(allocator, validator_count);
    defer allocator.free(all_pubkeys.attestation_pubkeys);
    defer allocator.free(all_pubkeys.proposal_pubkeys);

    const genesis_spec = types.GenesisSpec{
        .genesis_time = 1234,
        .validator_attestation_pubkeys = all_pubkeys.attestation_pubkeys,
        .validator_proposal_pubkeys = all_pubkeys.proposal_pubkeys,
    };

    var mock_chain = try stf.genMockChain(allocator, num_blocks, genesis_spec);
    defer mock_chain.deinit(allocator);
    defer mock_chain.genesis_state.validators.deinit();
    defer mock_chain.genesis_state.historical_block_hashes.deinit();
    defer mock_chain.genesis_state.justified_slots.deinit();
    defer mock_chain.genesis_state.justifications_roots.deinit();
    defer mock_chain.genesis_state.justifications_validators.deinit();

    const spec_name = try allocator.dupe(u8, "beamdev");
    const fork_digest = try allocator.dupe(u8, "12345678");
    defer allocator.free(spec_name);
    defer allocator.free(fork_digest);
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 8,
        },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const test_thread_pool = try initTestThreadPool();
    defer test_thread_pool.deinit();
    var fork_choice = try ForkChoice.init(allocator, .{
        .config = chain_config,
        .anchorState = &mock_chain.genesis_state,
        .logger = zeam_logger_config.logger(.forkchoice),
        .thread_pool = test_thread_pool,
    });
    defer fork_choice.deinit();

    // Seed two signatures so `aggregate` has enough work to exercise the
    // FFI-bearing path this mutex-contract test is guarding.
    const attestation_data = types.AttestationData{
        .slot = 0,
        .head = .{ .root = fork_choice.head.blockRoot, .slot = 0 },
        .target = .{ .root = fork_choice.head.blockRoot, .slot = 0 },
        .source = .{ .root = fork_choice.head.blockRoot, .slot = 0 },
    };
    inline for ([_]u32{ 0, 1 }) |validator_id| {
        const attestation = types.Attestation{ .validator_id = validator_id, .data = attestation_data };
        const signature = try key_manager.signAttestation(&attestation, allocator);
        try fork_choice.onSignedAttestation(.{
            .validator_id = validator_id,
            .message = attestation_data,
            .signature = signature,
        });
    }

    // Hold the forkchoice main mutex exclusive on the test thread for
    // the entire aggregator-thread lifetime. If `aggregate` (still)
    // calls `mutex.lock()`, the aggregator deadlocks and `join()`
    // never returns; the surrounding test runner watchdog will then
    // fail the test.
    fork_choice.mutex.lock();
    defer fork_choice.mutex.unlock();

    const Worker = struct {
        fork_choice: *ForkChoice,
        state: *const types.BeamState,
        result: anyerror![]types.SignedAggregatedAttestation = undefined,

        fn run(ctx: *@This()) void {
            ctx.result = ctx.fork_choice.aggregateForSlots(ctx.state, &.{0});
        }
    };
    var worker: Worker = .{ .fork_choice = &fork_choice, .state = &mock_chain.genesis_state };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    thread.join();

    const aggregations = try worker.result;
    defer {
        for (aggregations) |*signed_aggregation| {
            signed_aggregation.deinit();
        }
        allocator.free(aggregations);
    }

    try std.testing.expectEqual(@as(usize, 1), aggregations.len);
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
        .proposer_index = 0,
        .blockRoot = createTestRoot(block_root_byte),
        .parentRoot = createTestRoot(parent_root_byte),
        .stateRoot = createTestRoot(0x00),
        .timeliness = true,
        .confirmed = true,
    };
}

test "protoarray tie-break aligns with leanSpec hash ordering" {
    const allocator = std.testing.allocator;

    const anchor_block = createTestProtoBlock(0, 0xAA, 0x00);
    var proto_array = try ProtoArray.init(allocator, anchor_block);
    defer proto_array.nodes.deinit(proto_array.allocator);
    defer proto_array.indices.deinit();

    // Equal-weight siblings with different slots.
    // leanSpec picks lexicographically larger root, not higher slot.
    try proto_array.onBlock(createTestProtoBlock(2, 0x10, 0xAA), 2);
    try proto_array.onBlock(createTestProtoBlock(1, 0x20, 0xAA), 2);

    var deltas = try allocator.alloc(isize, proto_array.nodes.items.len);
    defer allocator.free(deltas);
    @memset(deltas, 0);
    deltas[1] = 1;
    deltas[2] = 1;

    try proto_array.applyDeltasUnlocked(deltas, 0);

    const anchor_idx = proto_array.indices.get(createTestRoot(0xAA)).?;
    const best_child_idx = proto_array.nodes.items[anchor_idx].bestChild.?;
    const best_child = proto_array.nodes.items[best_child_idx];

    try std.testing.expect(std.mem.eql(u8, &best_child.blockRoot, &createTestRoot(0x20)));
    try std.testing.expectEqual(@as(types.Slot, 1), best_child.slot);
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
    const fork_digest = try allocator.dupe(u8, "12345678");
    defer allocator.free(spec_name);
    defer allocator.free(fork_digest);
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 8,
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
    defer proto_array.nodes.deinit(proto_array.allocator);
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
        .slot_clock = zeam_utils.SlotTimeClock.init(8 * constants.INTERVALS_PER_SLOT, 8, 0),
        .latest_justified = anchorCP,
        .latest_finalized = anchorCP,
    };

    const test_thread_pool = try initTestThreadPool();
    defer test_thread_pool.deinit();
    var fork_choice = ForkChoice{
        .allocator = allocator,
        .protoArray = proto_array,
        .anchorState = &beam_state,
        .config = chain_config,
        .fcStore = fc_store,
        .attestations = std.AutoHashMap(usize, AttestationTracker).init(allocator),
        .head = createTestProtoBlock(8, 0xFF, 0xEE), // Head is F
        .safeTarget = createTestProtoBlock(8, 0xFF, 0xEE),
        .deltas = .empty,
        .logger = module_logger,
        .mutex = zeam_utils.SyncRwLock{},
        .attestation_signatures = SignaturesMap.init(allocator),
        .latest_new_aggregated_payloads = AggregatedPayloadsMap.init(allocator),
        .latest_known_aggregated_payloads = AggregatedPayloadsMap.init(allocator),
        .latest_block_aggregated_payloads = AggregatedPayloadsMap.init(allocator),
        .latest_block_aggregated_payloads_slot = null,
        .signatures_mutex = zeam_utils.SyncMutex{},
        .status = .ready,
        .thread_pool = test_thread_pool,
        .last_node_tick_time_ms = null,
    };
    defer fork_choice.attestations.deinit();
    defer fork_choice.deltas.deinit(fork_choice.allocator);
    defer fork_choice.attestation_signatures.deinit();
    defer deinitAggregatedPayloadsMap(allocator, &fork_choice.latest_known_aggregated_payloads);
    defer deinitAggregatedPayloadsMap(allocator, &fork_choice.latest_new_aggregated_payloads);
    defer deinitAggregatedPayloadsMap(allocator, &fork_choice.latest_block_aggregated_payloads);
    defer if (fork_choice.saved_pre_merge_new_coverage) |*cov| cov.deinit(allocator);

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

fn stageAggregatedAttestation(
    allocator: Allocator,
    fork_choice: *ForkChoice,
    signed_attestation: types.SignedAttestation,
) !void {
    try fork_choice.onSignedAttestation(signed_attestation);

    var proof = try types.TypeOneMultiSignature.init(allocator);
    defer proof.deinit();

    try types.aggregationBitsSet(&proof.participants, @intCast(signed_attestation.validator_id), true);

    try fork_choice.storeAggregatedPayload(&signed_attestation.message, proof, false);
}

// Rebase tests build ForkChoice structs in helper functions that outlive the helper scope.
// Keep logger config at file scope so ModuleLogger pointers remain valid.
var rebase_test_logger_config = zeam_utils.getTestLoggerConfig();

fn deinitAggregatedPayloadsList(allocator: Allocator, list: *AggregatedPayloadsList) void {
    for (list.items) |*stored| {
        stored.proof.deinit();
        if (stored.source_payload_participants) |*bits| bits.deinit();
        if (stored.source_gossip_participants) |*bits| bits.deinit();
    }
    list.deinit(allocator);
}

fn deinitAggregatedPayloadsMap(allocator: Allocator, map: *AggregatedPayloadsMap) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        deinitAggregatedPayloadsList(allocator, entry.value_ptr);
    }
    map.deinit();
}

/// Deep-clone an `AggregatedPayloadsMap`. Each stored
/// `AggregatedSignatureProof` is `sszClone`d so the destination owns
/// its own Rust XMSS handle (independent refcount). Caller releases
/// via `deinitAggregatedPayloadsMap`.
fn cloneAggregatedPayloadsMap(
    allocator: Allocator,
    src: *const AggregatedPayloadsMap,
) !AggregatedPayloadsMap {
    var dst = AggregatedPayloadsMap.init(allocator);
    errdefer deinitAggregatedPayloadsMap(allocator, &dst);

    var it = src.iterator();
    while (it.next()) |entry| {
        const gop = try dst.getOrPut(entry.key_ptr.*);
        if (!gop.found_existing) gop.value_ptr.* = .empty;

        try gop.value_ptr.ensureTotalCapacityPrecise(allocator, entry.value_ptr.items.len);
        for (entry.value_ptr.items) |*stored| {
            var cloned_proof: types.TypeOneMultiSignature = undefined;
            try types.sszClone(allocator, types.TypeOneMultiSignature, stored.proof, &cloned_proof);
            errdefer cloned_proof.deinit();

            var cloned_source_payload: ?types.AggregationBits = null;
            if (stored.source_payload_participants) |source_payload| {
                var bits: types.AggregationBits = undefined;
                try types.sszClone(allocator, types.AggregationBits, source_payload, &bits);
                errdefer bits.deinit();
                cloned_source_payload = bits;
            }
            var cloned_source_gossip: ?types.AggregationBits = null;
            if (stored.source_gossip_participants) |source_gossip| {
                var bits: types.AggregationBits = undefined;
                try types.sszClone(allocator, types.AggregationBits, source_gossip, &bits);
                errdefer bits.deinit();
                cloned_source_gossip = bits;
            }

            try gop.value_ptr.append(allocator, .{
                .slot = stored.slot,
                .proof = cloned_proof,
                .source_payload_participants = cloned_source_payload,
                .source_gossip_participants = cloned_source_gossip,
            });
        }
    }
    return dst;
}

/// Owned snapshot of the three signature/aggregation maps that
/// `aggregateUnlocked` reads. Taken under `signatures_mutex` and
/// then operated on outside the lock so the heavy XMSS FFI does
/// not block libxev / chain-worker writers.
const AggregateSnapshot = struct {
    signatures: types.SignaturesMap,
    new_payloads: AggregatedPayloadsMap,
    known_payloads: AggregatedPayloadsMap,

    /// Acquires `fork_choice.signatures_mutex`, deep-clones the three
    /// maps into freshly-allocated owned copies, then releases the
    /// lock. Cost is dominated by `sszClone` of every
    /// `AggregatedSignatureProof` (Rust FFI handle clone).
    fn takeUnderLock(fork_choice: *ForkChoice) !AggregateSnapshot {
        const allocator = fork_choice.allocator;

        fork_choice.signatures_mutex.lock();
        defer fork_choice.signatures_mutex.unlock();

        var signatures = types.SignaturesMap.init(allocator);
        errdefer signatures.deinit();

        var src_sig_it = fork_choice.attestation_signatures.iterator();
        while (src_sig_it.next()) |entry| {
            var inner = types.SignaturesMap.InnerMap.init(allocator);
            errdefer inner.deinit();
            try inner.ensureTotalCapacity(@intCast(entry.value_ptr.count()));

            var inner_it = entry.value_ptr.iterator();
            while (inner_it.next()) |vid_entry| {
                try inner.put(vid_entry.key_ptr.*, vid_entry.value_ptr.*);
            }

            try signatures.put(entry.key_ptr.*, inner);
        }

        var new_payloads = try cloneAggregatedPayloadsMap(allocator, &fork_choice.latest_new_aggregated_payloads);
        errdefer deinitAggregatedPayloadsMap(allocator, &new_payloads);

        var known_payloads = try cloneAggregatedPayloadsMap(allocator, &fork_choice.latest_known_aggregated_payloads);
        errdefer deinitAggregatedPayloadsMap(allocator, &known_payloads);

        return .{
            .signatures = signatures,
            .new_payloads = new_payloads,
            .known_payloads = known_payloads,
        };
    }

    fn deinit(self: *AggregateSnapshot, allocator: Allocator) void {
        self.signatures.deinit();
        deinitAggregatedPayloadsMap(allocator, &self.new_payloads);
        deinitAggregatedPayloadsMap(allocator, &self.known_payloads);
    }
};

/// Returns true when an `att_data` in the aggregator's snapshot is
/// trivial under the operator's threshold and should be dropped before
/// `computeAggregatedSignatures` runs:
///   - no child payloads (neither `new` nor `known`) for this `att_data`, AND
///   - fewer than `min_inputs` local gossip sigs.
///
/// This is the AGGREGATOR-side policy. The FFI function
/// `computeAggregatedSignatures` itself is spec-pure and has no notion
/// of this threshold — block proposers would call it with no
/// pre-filtering so a chosen `att_data` with a lone gossip sig still
/// produces a valid (1-validator) aggregate for inclusion in the block.
///
/// Pure / unit-testable: takes counts, not maps.
fn isAggregatorTrivialInput(num_children: usize, num_gossip_sigs: usize, min_inputs: u32) bool {
    if (num_children > 0) return false;
    return num_gossip_sigs < @as(usize, min_inputs);
}

test "isAggregatorTrivialInput: any child makes it non-trivial" {
    try std.testing.expect(!isAggregatorTrivialInput(1, 0, 2));
    try std.testing.expect(!isAggregatorTrivialInput(1, 1, 2));
    try std.testing.expect(!isAggregatorTrivialInput(2, 5, 8));
}

test "isAggregatorTrivialInput threshold=2: 0 or 1 sig is trivial, 2+ is not" {
    try std.testing.expect(isAggregatorTrivialInput(0, 0, 2));
    try std.testing.expect(isAggregatorTrivialInput(0, 1, 2));
    try std.testing.expect(!isAggregatorTrivialInput(0, 2, 2));
    try std.testing.expect(!isAggregatorTrivialInput(0, 8, 2));
}

test "isAggregatorTrivialInput threshold=1 only drops empty inputs" {
    try std.testing.expect(isAggregatorTrivialInput(0, 0, 1));
    try std.testing.expect(!isAggregatorTrivialInput(0, 1, 1));
    try std.testing.expect(!isAggregatorTrivialInput(0, 2, 1));
}

test "isAggregatorTrivialInput higher thresholds skip more no-children inputs" {
    try std.testing.expect(isAggregatorTrivialInput(0, 1, 3));
    try std.testing.expect(isAggregatorTrivialInput(0, 2, 3));
    try std.testing.expect(!isAggregatorTrivialInput(0, 3, 3));
}

/// Walk the owned aggregator snapshot and drop every `att_data` entry
/// from `signatures` that is trivial under `min_inputs` (see
/// `isAggregatorTrivialInput`). The corresponding inner map is freed.
///
/// Untouched gossip sigs stay in the live `attestation_signatures` map
/// (the snapshot is a clone — pruning the snapshot does NOT touch the
/// live map) and naturally feed the next aggregation pass once any
/// peer payload arrives or another local sig accumulates on the same
/// `att_data`.
///
/// Logs a single debug line summarising the count + threshold so the
/// startup `aggregator threshold:` info line stays the only visible
/// boot-time mention of this knob; per-pass detail is at debug level.
fn pruneTrivialFromAggregateSnapshot(
    allocator: Allocator,
    snap: *AggregateSnapshot,
    min_inputs: u32,
    logger: zeam_utils.ModuleLogger,
) void {
    // `min_inputs <= 1` reduces to the pre-existing `0 sigs + 0
    // children` skip already inside `computeAggregatedSignatures`, so
    // the pre-filter is a no-op and we can return early.
    if (min_inputs <= 1) return;

    // Collect keys to remove first — std.AutoHashMap does not support
    // removal during iteration.
    var to_drop: std.ArrayList(types.AttestationData) = .empty;
    defer to_drop.deinit(allocator);

    var it = snap.signatures.iterator();
    while (it.next()) |entry| {
        const att_data = entry.key_ptr.*;
        const num_sigs: usize = @intCast(entry.value_ptr.count());

        const num_children: usize = blk: {
            var n: usize = 0;
            if (snap.new_payloads.get(att_data)) |list| n += list.items.len;
            if (snap.known_payloads.get(att_data)) |list| n += list.items.len;
            break :blk n;
        };

        if (isAggregatorTrivialInput(num_children, num_sigs, min_inputs)) {
            to_drop.append(allocator, att_data) catch {
                // Best-effort filtering: on OOM we skip the rest of the
                // sweep and let `computeAggregatedSignatures` aggregate
                // whatever's still there. Correctness is preserved
                // (over-aggregation, never under), and OOM here is
                // exceedingly unlikely given how small the key list is.
                return;
            };
        }
    }

    if (to_drop.items.len == 0) return;

    for (to_drop.items) |att_data| {
        snap.signatures.removeAndDeinit(att_data);
    }

    logger.debug(
        "aggregator pre-filter: dropped {d} trivial att_data (threshold min_aggregation_inputs={d})",
        .{ to_drop.items.len, min_inputs },
    );
}

fn collectCoverageFromPayloads(
    map: *AggregatedPayloadsMap,
    slot: types.Slot,
    committee_count: types.SubnetId,
    seen: []bool,
    combined_seen: []bool,
    has_subnet: []bool,
    combined_has_subnet: []bool,
) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        if (entry.key_ptr.slot != slot) continue;
        for (entry.value_ptr.items) |*stored| {
            if (stored.slot != slot) continue;
            for (0..stored.proof.participants.len()) |validator_index| {
                if (validator_index >= seen.len) continue;
                if (!(stored.proof.participants.get(validator_index) catch false)) continue;

                const subnet_id = types.computeSubnetId(@intCast(validator_index), committee_count) catch continue;
                const subnet_index: usize = @intCast(subnet_id);
                if (subnet_index >= has_subnet.len) continue;

                seen[validator_index] = true;
                combined_seen[validator_index] = true;
                has_subnet[subnet_index] = true;
                combined_has_subnet[subnet_index] = true;
            }
        }
    }
}

fn collectSourceCoverageFromPayloadsForData(
    map: *AggregatedPayloadsMap,
    att_data: types.AttestationData,
    committee_count: types.SubnetId,
    payload_seen: []bool,
    gossip_seen: []bool,
) void {
    const payloads = map.get(att_data) orelse return;
    for (payloads.items) |*stored| {
        if (stored.slot != att_data.slot) continue;

        if (stored.source_payload_participants) |source_payload| {
            for (0..source_payload.len()) |validator_index| {
                markCoverageValidatorOnly(source_payload, validator_index, committee_count, payload_seen);
            }
        } else {
            // Unknown/legacy source: treat the child payload itself as payload-originated.
            for (0..stored.proof.participants.len()) |validator_index| {
                markCoverageValidatorOnly(stored.proof.participants, validator_index, committee_count, payload_seen);
            }
        }

        if (stored.source_gossip_participants) |source_gossip| {
            for (0..source_gossip.len()) |validator_index| {
                markCoverageValidatorOnly(source_gossip, validator_index, committee_count, gossip_seen);
            }
        }
    }
}

fn markCoverageIfParticipant(
    participants: types.AggregationBits,
    validator_index: usize,
    committee_count: types.SubnetId,
    seen: []bool,
    has_subnet: []bool,
) void {
    if (validator_index >= seen.len) return;
    if (!(participants.get(validator_index) catch false)) return;

    const subnet_id = types.computeSubnetId(@intCast(validator_index), committee_count) catch return;
    const subnet_index: usize = @intCast(subnet_id);
    if (subnet_index >= has_subnet.len) return;

    seen[validator_index] = true;
    has_subnet[subnet_index] = true;
}

/// Mark validator-level coverage without tracking per-subnet bits.
/// Validates subnet membership to keep the same inclusion criteria as
/// markCoverageIfParticipant but does not set has_subnet.
fn markCoverageValidatorOnly(
    participants: types.AggregationBits,
    validator_index: usize,
    committee_count: types.SubnetId,
    seen: []bool,
) void {
    if (validator_index >= seen.len) return;
    if (!(participants.get(validator_index) catch false)) return;
    _ = types.computeSubnetId(@intCast(validator_index), committee_count) catch return;
    seen[validator_index] = true;
}

fn collectCoverageFromSignaturesForData(
    map: *const SignaturesMap,
    att_data: types.AttestationData,
    committee_count: types.SubnetId,
    seen: []bool,
) void {
    const signatures = map.get(att_data) orelse return;
    var it = signatures.iterator();
    while (it.next()) |entry| {
        const validator_index: usize = @intCast(entry.key_ptr.*);
        if (validator_index >= seen.len) continue;
        if (std.mem.eql(u8, &entry.value_ptr.signature, &ZERO_SIGBYTES)) continue;
        _ = types.computeSubnetId(@intCast(validator_index), committee_count) catch continue;
        seen[validator_index] = true;
    }
}

/// Aggregate validator/subnet coverage of every individual gossip signature
/// in `map` whose `AttestationData.slot == slot`. Used by
/// `logNewPayloadsCoverageForAggregation` to surface the local-subnet input
/// that `latest_new_aggregated_payloads` alone does not see (#899).
fn collectGossipSigCoverageForSlot(
    map: *const SignaturesMap,
    slot: types.Slot,
    committee_count: types.SubnetId,
    validator_count: usize,
    seen: []bool,
    has_subnet: []bool,
) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        if (entry.key_ptr.slot != slot) continue;
        var vid_it = entry.value_ptr.iterator();
        while (vid_it.next()) |sig_entry| {
            const validator_index: usize = @intCast(sig_entry.key_ptr.*);
            if (validator_index >= validator_count) continue;
            if (validator_index >= seen.len) continue;
            if (std.mem.eql(u8, &sig_entry.value_ptr.signature, &ZERO_SIGBYTES)) continue;
            const subnet_id = types.computeSubnetId(@intCast(validator_index), committee_count) catch continue;
            const subnet_index: usize = @intCast(subnet_id);
            if (subnet_index >= has_subnet.len) continue;
            seen[validator_index] = true;
            has_subnet[subnet_index] = true;
        }
    }
}

fn collectCoverageFromAggregatedAttestation(
    agg_att: types.AggregatedAttestation,
    committee_count: types.SubnetId,
    seen: []bool,
    has_subnet: []bool,
) void {
    for (0..agg_att.aggregation_bits.len()) |validator_index| {
        if (validator_index >= seen.len) continue;
        if (!(agg_att.aggregation_bits.get(validator_index) catch false)) continue;

        const subnet_id = types.computeSubnetId(@intCast(validator_index), committee_count) catch continue;
        const subnet_index: usize = @intCast(subnet_id);
        if (subnet_index >= has_subnet.len) continue;

        seen[validator_index] = true;
        has_subnet[subnet_index] = true;
    }
}

fn appendCoverageSection(
    allocator: Allocator,
    out: *std.ArrayList(u8),
    label: []const u8,
    seen: []const bool,
    has_subnet: []const bool,
    validator_count: usize,
    committee_count: types.SubnetId,
) !void {
    try appendFmt(allocator, out, "{s}=", .{label});

    var wrote_any = false;
    for (has_subnet, 0..) |has, subnet_index| {
        if (!has) continue;
        if (wrote_any) try out.appendSlice(allocator, ",");

        const coverage = countSubnetSeen(seen, @intCast(subnet_index), committee_count);
        const total = countSubnetValidators(validator_count, @intCast(subnet_index), committee_count);
        try appendFmt(allocator, out, "subnet{d}={d}/{d}({d:.2}%)", .{
            subnet_index,
            coverage,
            total,
            coveragePct(coverage, total),
        });
        wrote_any = true;
    }

    if (!wrote_any) try out.appendSlice(allocator, "none");
}

fn appendFmt(allocator: Allocator, out: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(text);
    try out.appendSlice(allocator, text);
}

fn countSeen(seen: []const bool) usize {
    var count: usize = 0;
    for (seen) |is_seen| {
        if (is_seen) count += 1;
    }
    return count;
}

fn observeAggregateBuildPhase(comptime phase: []const u8, start_ns: i128) void {
    const elapsed_s = phaseElapsedSeconds(start_ns);
    zeam_metrics.metrics.zeam_pq_sig_aggregated_signatures_building_phase_seconds.observe(
        .{ .phase = phase },
        elapsed_s,
    ) catch {};
}

fn observeProposalBuildPhase(comptime phase: []const u8, start_ns: i128) void {
    const elapsed_s = phaseElapsedSeconds(start_ns);
    zeam_metrics.metrics.lean_block_proposal_attestation_build_phase_seconds.observe(
        .{ .phase = phase },
        elapsed_s,
    ) catch {};
}

fn phaseElapsedSeconds(start_ns: i128) f32 {
    const end_ns = zeam_utils.monotonicTimestampNs();
    const elapsed_ns: i128 = if (end_ns >= start_ns) end_ns - start_ns else 0;
    // Histogram seconds are f32; precision below roughly 100 ns is intentionally
    // irrelevant for these phase buckets. Phase sums are an attribution view
    // rather than an exact replacement for the path's total wall-clock histogram.
    return @as(f32, @floatFromInt(elapsed_ns)) / @as(f32, @floatFromInt(std.time.ns_per_s));
}

fn recordAggregateCoverageMetrics(
    section: []const u8,
    seen: []const bool,
    has_subnet: []const bool,
    committee_count: types.SubnetId,
) void {
    zeam_metrics.metrics.lean_attestation_aggregate_coverage_validators.set(
        .{ .section = section, .subnet = "combined" },
        @intCast(countSeen(seen)),
    ) catch {};
    zeam_metrics.metrics.lean_attestation_aggregate_coverage_subnets.set(
        .{ .section = section },
        @intCast(countSeen(has_subnet)),
    ) catch {};

    for (has_subnet, 0..) |_, subnet_index| {
        var subnet_label_buf: [32]u8 = undefined;
        const subnet_label = std.fmt.bufPrint(&subnet_label_buf, "subnet_{d}", .{subnet_index}) catch continue;
        zeam_metrics.metrics.lean_attestation_aggregate_coverage_validators.set(
            .{ .section = section, .subnet = subnet_label },
            @intCast(countSubnetSeen(seen, @intCast(subnet_index), committee_count)),
        ) catch {};
    }
}

fn countSubnetSeen(seen: []const bool, subnet_id: types.SubnetId, committee_count: types.SubnetId) usize {
    var count: usize = 0;
    for (seen, 0..) |is_seen, validator_index| {
        if (!is_seen) continue;
        const validator_subnet = types.computeSubnetId(@intCast(validator_index), committee_count) catch continue;
        if (validator_subnet == subnet_id) count += 1;
    }
    return count;
}

fn countSubnetValidators(validator_count: usize, subnet_id: types.SubnetId, committee_count: types.SubnetId) usize {
    var count: usize = 0;
    for (0..validator_count) |validator_index| {
        const validator_subnet = types.computeSubnetId(@intCast(validator_index), committee_count) catch continue;
        if (validator_subnet == subnet_id) count += 1;
    }
    return count;
}

fn coveragePct(covered: usize, total: usize) f64 {
    if (total == 0) return 0;
    return (@as(f64, @floatFromInt(covered)) * 100.0) / @as(f64, @floatFromInt(total));
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
    fork_digest: []u8,
    thread_pool: *ThreadPool,
} {
    const spec_name = try allocator.dupe(u8, "beamdev");
    const fork_digest = try allocator.dupe(u8, "12345678");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 8,
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
        .slot_clock = zeam_utils.SlotTimeClock.init(8 * constants.INTERVALS_PER_SLOT, 8, 0),
        .latest_justified = anchorCP,
        .latest_finalized = anchorCP,
    };

    const module_logger = rebase_test_logger_config.logger(.forkchoice);

    const test_thread_pool = try initTestThreadPool();
    errdefer test_thread_pool.deinit();
    const fork_choice = ForkChoice{
        .allocator = allocator,
        .protoArray = proto_array,
        .anchorState = &mock_chain.genesis_state,
        .config = chain_config,
        .fcStore = fc_store,
        .attestations = std.AutoHashMap(usize, AttestationTracker).init(allocator),
        .head = createTestProtoBlock(8, 0xFF, 0xEE), // Head is F
        .safeTarget = createTestProtoBlock(8, 0xFF, 0xEE),
        .deltas = .empty,
        .logger = module_logger,
        .mutex = zeam_utils.SyncRwLock{},
        .attestation_signatures = SignaturesMap.init(allocator),
        .latest_new_aggregated_payloads = AggregatedPayloadsMap.init(allocator),
        .latest_known_aggregated_payloads = AggregatedPayloadsMap.init(allocator),
        .latest_block_aggregated_payloads = AggregatedPayloadsMap.init(allocator),
        .latest_block_aggregated_payloads_slot = null,
        .signatures_mutex = zeam_utils.SyncMutex{},
        .status = .ready,
        .thread_pool = test_thread_pool,
        .last_node_tick_time_ms = null,
    };

    return .{
        .fork_choice = fork_choice,
        .spec_name = spec_name,
        .fork_digest = fork_digest,
        .thread_pool = test_thread_pool,
    };
}

/// Test context that consolidates setup and cleanup for rebase tests.
/// This reduces the ~12-line defer block duplication across all tests.
const RebaseTestContext = struct {
    mock_chain: stf.MockChainData,
    fork_choice: ForkChoice,
    spec_name: []u8,
    fork_digest: []u8,
    thread_pool: *ThreadPool,
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
        errdefer allocator.free(test_data.fork_digest);
        errdefer test_data.fork_choice.protoArray.nodes.deinit(test_data.fork_choice.allocator);
        errdefer test_data.fork_choice.protoArray.indices.deinit();
        errdefer test_data.fork_choice.attestations.deinit();
        errdefer test_data.fork_choice.deltas.deinit(test_data.fork_choice.allocator);
        errdefer test_data.fork_choice.attestation_signatures.deinit();
        errdefer deinitAggregatedPayloadsMap(allocator, &test_data.fork_choice.latest_known_aggregated_payloads);
        errdefer deinitAggregatedPayloadsMap(allocator, &test_data.fork_choice.latest_new_aggregated_payloads);
        errdefer deinitAggregatedPayloadsMap(allocator, &test_data.fork_choice.latest_block_aggregated_payloads);
        errdefer test_data.thread_pool.deinit();

        return .{
            .mock_chain = mock_chain,
            .fork_choice = test_data.fork_choice,
            .spec_name = test_data.spec_name,
            .fork_digest = test_data.fork_digest,
            .thread_pool = test_data.thread_pool,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RebaseTestContext) void {
        // Cleanup fork_choice components
        self.fork_choice.protoArray.nodes.deinit(self.allocator);
        self.fork_choice.protoArray.indices.deinit();
        self.fork_choice.attestations.deinit();
        self.fork_choice.deltas.deinit(self.allocator);
        self.fork_choice.attestation_signatures.deinit();
        deinitAggregatedPayloadsMap(self.allocator, &self.fork_choice.latest_known_aggregated_payloads);
        deinitAggregatedPayloadsMap(self.allocator, &self.fork_choice.latest_new_aggregated_payloads);
        deinitAggregatedPayloadsMap(self.allocator, &self.fork_choice.latest_block_aggregated_payloads);
        if (self.fork_choice.saved_pre_merge_new_coverage) |*cov| cov.deinit(self.allocator);
        self.allocator.free(self.spec_name);
        self.allocator.free(self.fork_digest);
        self.thread_pool.deinit();

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

    // Setup aggregated attestations: All 4 validators vote for F (index 5)
    for (0..4) |validator_id| {
        const att = createTestSignedAttestation(validator_id, createTestRoot(0xFF), 8);
        try stageAggregatedAttestation(allocator, &ctx.fork_choice, att);
    }
    _ = try ctx.fork_choice.acceptNewAttestations();

    // Apply deltas to establish weights and bestChild/bestDescendant
    const deltas = try ctx.fork_choice.computeDeltas(true);
    try ctx.fork_choice.applyDeltas(deltas, 0);

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

    // Setup aggregated attestations: All 4 validators vote for F (index 5)
    for (0..4) |validator_id| {
        const att = createTestSignedAttestation(validator_id, createTestRoot(0xFF), 8);
        try stageAggregatedAttestation(allocator, &ctx.fork_choice, att);
    }
    _ = try ctx.fork_choice.acceptNewAttestations();

    // Apply deltas to establish weights
    const deltas = try ctx.fork_choice.computeDeltas(true);
    try ctx.fork_choice.applyDeltas(deltas, 0);

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
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att0);

    const att1 = createTestSignedAttestation(1, createTestRoot(0xEE), 6); // E
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att1);

    const att2 = createTestSignedAttestation(2, createTestRoot(0xFF), 8); // F
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att2);

    const att3 = createTestSignedAttestation(3, createTestRoot(0xCC), 3); // C
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att3);

    _ = try ctx.fork_choice.acceptNewAttestations();
    _ = try ctx.fork_choice.computeDeltas(true);

    // Verify pre-rebase attestation indices
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 3); // D
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.index == 4); // E
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 5); // F
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown.?.index == 2); // C

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

    // Setup aggregated attestations as "new" (not yet accepted)
    const att0 = createTestSignedAttestation(0, createTestRoot(0xDD), 5); // D
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att0);

    const att1 = createTestSignedAttestation(1, createTestRoot(0xFF), 8); // F
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att1);

    _ = try ctx.fork_choice.computeDeltas(false);

    // Verify pre-rebase: latestNew is set, latestKnown is null
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestNew.?.index == 3);
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown == null);
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestNew.?.index == 5);
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown == null);

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
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att0);

    const att1 = createTestSignedAttestation(1, createTestRoot(0xEE), 6); // E (index 4)
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att1);

    const att2 = createTestSignedAttestation(2, createTestRoot(0xFF), 8); // F (index 5)
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att2);

    const att3 = createTestSignedAttestation(3, createTestRoot(0xCC), 3); // C (index 2)
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att3);

    _ = try ctx.fork_choice.acceptNewAttestations();
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
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att0);

    const att1 = createTestSignedAttestation(1, createTestRoot(0xBB), 1); // B (slot 1)
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att1);

    // Setup attestations on descendant nodes (will be preserved)
    const att2 = createTestSignedAttestation(2, createTestRoot(0x11), 4); // G (slot 4, fork)
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att2);

    const att3 = createTestSignedAttestation(3, createTestRoot(0xDD), 5); // D (slot 5)
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att3);

    _ = try ctx.fork_choice.acceptNewAttestations();
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
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att0_known);
    const att0_new = createTestSignedAttestation(0, createTestRoot(0xEE), 6); // E

    // Validator 1: latestKnown on B (slot 1, will be pruned), latestNew on F (slot 8 > 1)
    const att1_known = createTestSignedAttestation(1, createTestRoot(0xBB), 1); // B
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att1_known);
    const att1_new = createTestSignedAttestation(1, createTestRoot(0xFF), 8); // F

    // Validator 2: latestKnown on G (slot 4, preserved), latestNew on I (slot 7 > 4, preserved)
    const att2_known = createTestSignedAttestation(2, createTestRoot(0x11), 4); // G
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att2_known);
    const att2_new = createTestSignedAttestation(2, createTestRoot(0x33), 7); // I

    _ = try ctx.fork_choice.acceptNewAttestations();

    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att0_new);
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att1_new);
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att2_new);

    _ = try ctx.fork_choice.computeDeltas(true);
    _ = try ctx.fork_choice.computeDeltas(false);

    // Verify pre-rebase state
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 3); // D
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestNew.?.index == 4); // E
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.index == 1); // B
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestNew.?.index == 5); // F
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 6); // G
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestNew.?.index == 8); // I

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
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att);
    _ = try ctx.fork_choice.acceptNewAttestations();
    _ = try ctx.fork_choice.computeDeltas(true);

    // Record pre-rebase state
    const pre_node_count = ctx.fork_choice.protoArray.nodes.items.len;
    const pre_att_index = ctx.fork_choice.attestations.get(0).?.latestKnown.?.index;

    // Verify we have all 9 nodes
    try std.testing.expect(pre_node_count == 9);
    try std.testing.expect(pre_att_index == 5); // F

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
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att);
    _ = try ctx.fork_choice.acceptNewAttestations();
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
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att0);
    const att1 = createTestSignedAttestation(1, createTestRoot(0xFF), 8); // F
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att1);

    // Fork: validators 2, 3 on H and I (these are kept despite fork, slot >= 5)
    const att2 = createTestSignedAttestation(2, createTestRoot(0x22), 6); // H
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att2);
    const att3 = createTestSignedAttestation(3, createTestRoot(0x33), 7); // I
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att3);

    _ = try ctx.fork_choice.acceptNewAttestations();
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
    const validator_count: usize = 32;
    const num_blocks: usize = 4;
    var key_manager = try keymanager.getTestKeyManager(allocator, validator_count, num_blocks);
    defer key_manager.deinit();
    const all_pubkeys = try key_manager.getAllPubkeys(allocator, validator_count);
    defer allocator.free(all_pubkeys.attestation_pubkeys);
    defer allocator.free(all_pubkeys.proposal_pubkeys);

    const genesis_spec = types.GenesisSpec{
        .genesis_time = 1234,
        .validator_attestation_pubkeys = all_pubkeys.attestation_pubkeys,
        .validator_proposal_pubkeys = all_pubkeys.proposal_pubkeys,
    };

    var mock_chain = try stf.genMockChain(allocator, num_blocks, genesis_spec);
    defer mock_chain.deinit(allocator);
    defer mock_chain.genesis_state.validators.deinit();
    defer mock_chain.genesis_state.historical_block_hashes.deinit();
    defer mock_chain.genesis_state.justified_slots.deinit();
    defer mock_chain.genesis_state.justifications_roots.deinit();
    defer mock_chain.genesis_state.justifications_validators.deinit();

    const spec_name = try allocator.dupe(u8, "beamdev");
    const fork_digest = try allocator.dupe(u8, "12345678");
    defer allocator.free(spec_name);
    defer allocator.free(fork_digest);
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 8,
        },
    };

    // Build smaller tree: A -> B -> C -> D
    const anchor_block = createTestProtoBlock(0, 0xAA, 0x00);
    var proto_array = try ProtoArray.init(allocator, anchor_block);
    defer proto_array.nodes.deinit(proto_array.allocator);
    defer proto_array.indices.deinit();

    try proto_array.onBlock(createTestProtoBlock(1, 0xBB, 0xAA), 1);
    try proto_array.onBlock(createTestProtoBlock(2, 0xCC, 0xBB), 2);
    try proto_array.onBlock(createTestProtoBlock(3, 0xDD, 0xCC), 3);

    const anchorCP = types.Checkpoint{ .slot = 0, .root = createTestRoot(0xAA) };
    const fc_store = ForkChoiceStore{
        .slot_clock = zeam_utils.SlotTimeClock.init(3 * constants.INTERVALS_PER_SLOT, 3, 0),
        .latest_justified = anchorCP,
        .latest_finalized = anchorCP,
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.forkchoice);

    const test_thread_pool = try initTestThreadPool();
    defer test_thread_pool.deinit();
    var fork_choice = ForkChoice{
        .allocator = allocator,
        .protoArray = proto_array,
        .anchorState = &mock_chain.genesis_state,
        .config = chain_config,
        .fcStore = fc_store,
        .attestations = std.AutoHashMap(usize, AttestationTracker).init(allocator),
        .head = createTestProtoBlock(3, 0xDD, 0xCC),
        .safeTarget = createTestProtoBlock(3, 0xDD, 0xCC),
        .deltas = .empty,
        .logger = module_logger,
        .mutex = zeam_utils.SyncRwLock{},
        .attestation_signatures = SignaturesMap.init(allocator),
        .latest_new_aggregated_payloads = AggregatedPayloadsMap.init(allocator),
        .latest_known_aggregated_payloads = AggregatedPayloadsMap.init(allocator),
        .latest_block_aggregated_payloads = AggregatedPayloadsMap.init(allocator),
        .latest_block_aggregated_payloads_slot = null,
        .signatures_mutex = zeam_utils.SyncMutex{},
        .status = .ready,
        .thread_pool = test_thread_pool,
        .last_node_tick_time_ms = null,
    };
    // Note: We don't defer proto_array.nodes/indices.deinit() here because they're
    // moved into fork_choice and will be deinitialized separately
    defer fork_choice.attestations.deinit();
    defer fork_choice.deltas.deinit(fork_choice.allocator);
    defer fork_choice.attestation_signatures.deinit();
    defer deinitAggregatedPayloadsMap(allocator, &fork_choice.latest_known_aggregated_payloads);
    defer deinitAggregatedPayloadsMap(allocator, &fork_choice.latest_new_aggregated_payloads);
    defer deinitAggregatedPayloadsMap(allocator, &fork_choice.latest_block_aggregated_payloads);
    defer if (fork_choice.saved_pre_merge_new_coverage) |*cov| cov.deinit(allocator);

    // Setup attestations for all validators
    // Distribute across C and D
    for (0..validator_count) |validator_id| {
        const target = if (validator_id % 2 == 0) createTestRoot(0xCC) else createTestRoot(0xDD);
        const slot: types.Slot = if (validator_id % 2 == 0) 2 else 3;
        const att = createTestSignedAttestation(validator_id, target, slot);
        try stageAggregatedAttestation(allocator, &fork_choice, att);
    }

    _ = try fork_choice.acceptNewAttestations();
    _ = try fork_choice.computeDeltas(true);

    // Verify all attestations are set
    for (0..validator_count) |validator_id| {
        const tracker = fork_choice.attestations.get(validator_id);
        try std.testing.expect(tracker != null);
        try std.testing.expect(tracker.?.latestKnown != null);
    }

    // Rebase to C (0xCC)
    try fork_choice.rebase(createTestRoot(0xCC), null);

    // Verify 2 nodes remain: C, D
    try std.testing.expect(fork_choice.protoArray.nodes.items.len == 2);

    // Verify all attestations are correctly updated
    for (0..validator_count) |validator_id| {
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
        try stageAggregatedAttestation(allocator, &ctx.fork_choice, att);
    }

    _ = try ctx.fork_choice.acceptNewAttestations();
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

test "rebase: bestChild/bestDescendant null handled in rebase (issue #545)" {
    // ========================================
    // Test: rebase does not panic when a node has bestChild set but bestDescendant null
    // ========================================
    //
    // Regression test for issue #545:
    //   https://github.com/blockblaz/zeam/issues/545
    //
    // When applyDeltas is called with cutoff_weight > 0, nodes below cutoff can have
    // bestDescendant = null while their parent still sets bestChild to them. Rebase
    // now treats null bestDescendant as bestChild for index remapping instead of panicking.

    const allocator = std.testing.allocator;
    var ctx = try RebaseTestContext.init(allocator, 4);
    defer ctx.deinit();

    // Only vote on canonical chain — fork branch has zero weight
    for (0..4) |validator_id| {
        const att = createTestSignedAttestation(validator_id, createTestRoot(0xFF), 8);
        try ctx.fork_choice.onSignedAttestation(att);
    }

    // applyDeltas with cutoff_weight=1 can leave some nodes with bestChild set, bestDescendant null
    const deltas = try ctx.fork_choice.computeDeltas(true);
    try ctx.fork_choice.applyDeltas(deltas, 1);

    // Rebase to C — must not panic (previously hit "null best descendant for a non null best child")
    try ctx.fork_choice.rebase(createTestRoot(0xCC), null);

    // After rebase: if bestDescendant was null (due to cutoff), it remains null.
    // This is the correct behavior - rebase preserves the null state rather than remapping.
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 7);
    // The invariant "bestChild != null implies bestDescendant != null" does NOT hold
    // when cutoff_weight is used, as nodes below cutoff can have bestDescendant = null.
    // Rebase correctly preserves this state.
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
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att0);
    const att1 = createTestSignedAttestation(1, createTestRoot(0xFF), 8); // F
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att1);

    // Attestations on fork branch (will be remapped)
    const att2 = createTestSignedAttestation(2, createTestRoot(0x22), 6); // H
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att2);
    const att3 = createTestSignedAttestation(3, createTestRoot(0x33), 7); // I
    try stageAggregatedAttestation(allocator, &ctx.fork_choice, att3);

    _ = try ctx.fork_choice.acceptNewAttestations();
    _ = try ctx.fork_choice.computeDeltas(true);

    // Verify pre-rebase state
    try std.testing.expect(ctx.fork_choice.protoArray.nodes.items.len == 9);
    try std.testing.expect(ctx.fork_choice.attestations.get(0).?.latestKnown.?.index == 3); // D
    try std.testing.expect(ctx.fork_choice.attestations.get(1).?.latestKnown.?.index == 5); // F
    try std.testing.expect(ctx.fork_choice.attestations.get(2).?.latestKnown.?.index == 7); // H
    try std.testing.expect(ctx.fork_choice.attestations.get(3).?.latestKnown.?.index == 8); // I

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
