//! Block deconstruction — devnet5 port of leanSpec #717 `_deconstruct_block_into_store`
//! (`subspecs/sync/service.py`).
//!
//! On block import the per-attestation proofs are locked inside the block's single Type-2 proof.
//! For each block attestation that covers validators not already held locally, we split that
//! attestation's Type-1 out of the Type-2 (`split_type_2_by_msg`), merge it with disjoint local
//! partial proofs for the same data into one higher-coverage Type-1, write it into the pending
//! pool (`latest_new_aggregated_payloads`), and return the combined aggregate for the aggregator
//! role to gossip.
//!
//! Architectural note (zeam vs leanSpec): in leanSpec the pool IS the fork-choice weight source, so
//! block-imported votes are deferred one slot via this path. zeam uses protoarray + the
//! `AttestationTracker`, which is fed eagerly by `onAttestation(is_from_block=true)` in `chain.onBlock`
//! — so weight already landed and deconstruction here only recovers proofs into the pool for block
//! re-aggregation + aggregator gossip. It is therefore NOT a correctness/safety path.
//!
//! Phase split (compute/commit) so a fallible recovery never leaves the store half-mutated relative
//! to the fork-choice mutations: COMPUTE (fallible, before `forkChoice.onBlock`) does the prover work
//! and stages results without touching the pool; COMMIT (infallible, after the fork-choice mutations)
//! inserts staged proofs and best-effort drops superseded partials.

const std = @import("std");
const ssz = @import("ssz");
const types = @import("@zeam/types");
const xmss = @import("@zeam/xmss");
const zeam_utils = @import("@zeam/utils");

const ForkChoice = @import("forkchoice.zig").ForkChoice;

const Allocator = std.mem.Allocator;
const AggregationBits = types.AggregationBits;
const TypeOneMultiSignature = types.TypeOneMultiSignature;

const LOG_INV_RATE = types.LOG_INV_RATE_PROD;

/// Max children per `aggregate_type_1` call, matching leanMultisig `MAX_RECURSIONS`. The block
/// component plus the selected local partials must stay within this, or the prover asserts/aborts
/// (caught as a failed recovery). Selection below is capped to MAX_AGGREGATE_CHILDREN - 1 partials.
const MAX_AGGREGATE_CHILDREN: usize = 16;

/// Master gate for block deconstruction. Kept DISABLED, but the reason has narrowed.
///
/// The prior chain-liveness regression (justification stuck at 0 with deconstruction on) was the
/// non-disjoint child selection in deconstructCompute — overlapping validators across aggregate
/// children produced a combined proof whose pubkey multiset no longer matched its collapsed
/// aggregation_bits, so re-aggregated blocks failed verify and never reached quorum. That bug is
/// now fixed (strict-disjoint selection + child cap), and with it `enabled = true` justifies AND
/// finalizes correctly in the multi-node simtest.
///
/// The REMAINING blocker is throughput, not correctness: COMPUTE runs the split + aggregate prover
/// synchronously on the block-import path, which roughly halves chain progress in the simtest
/// (Head ~20 vs ~36 in the same window) and starves a late-joining node's sync (node3_sync fails).
/// Enabling for real requires moving COMPUTE onto an async worker queue, off the import critical
/// path. Until then the proof pool is simply not fed from imported blocks — safe in zeam because
/// fork-choice weight comes from the eager AttestationTracker (onAttestation(is_from_block=true)),
/// not this pool; only block-reaggregation/gossip coverage is reduced. TODO: async COMPUTE, then
/// flip to `true`.
pub const enabled = false;

/// One recovered attestation staged for commit: the combined Type-1 proof to insert into
/// `latest_new_aggregated_payloads`, plus the participant sets of the local partials it merged in
/// (so commit can best-effort drop those now-redundant entries).
const StagedEntry = struct {
    data: types.AttestationData,
    combined: TypeOneMultiSignature,
    superseded: std.ArrayList(AggregationBits),
};

pub const StagedDeconstruct = struct {
    entries: std.ArrayList(StagedEntry),
    allocator: Allocator,

    pub fn empty(allocator: Allocator) StagedDeconstruct {
        return .{ .entries = .empty, .allocator = allocator };
    }

    pub fn deinit(self: *StagedDeconstruct) void {
        for (self.entries.items) |*e| {
            e.combined.deinit();
            for (e.superseded.items) |*p| p.deinit();
            e.superseded.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
    }
};

/// SSZ-equality of two aggregation bitfields (length + every bit). Used to match a superseded
/// partial against the live pool entries at commit time.
fn aggBitsEqual(a: *const AggregationBits, b: *const AggregationBits) bool {
    if (a.len() != b.len()) return false;
    for (0..a.len()) |i| {
        const av = a.get(i) catch return false;
        const bv = b.get(i) catch return false;
        if (av != bv) return false;
    }
    return true;
}

/// COMPUTE phase (fallible) — runs BEFORE `forkChoice.onBlock`. Splits the block's Type-2 into
/// per-attestation Type-1s, merges with disjoint local partials, and stages combined proofs.
/// Mutates NOTHING in the fork choice. Caller owns the returned value and must `deinit` it.
///
/// MUST run on a worker thread (drives the prover). The caller must NOT hold `signatures_mutex`
/// or the main `mutex`.
pub fn deconstructCompute(
    allocator: Allocator,
    fork_choice: *ForkChoice,
    signed_block: *const types.SignedBlock,
    parent_state: *const types.BeamState,
) !StagedDeconstruct {
    var staged = StagedDeconstruct.empty(allocator);
    errdefer staged.deinit();

    // Deconstruction is gated OFF (see `enabled`). The old justify-stall was the non-disjoint
    // child selection below (now fixed); the remaining blocker is that this COMPUTE runs the
    // prover synchronously on the import path and ~halves simtest throughput. It is NOT a
    // correctness/safety feature in zeam (fork-choice weight comes from the eager
    // AttestationTracker via onAttestation(is_from_block=true), not the proof pool), so disabling
    // it only reduces block-reaggregation/gossip coverage. Module + wiring are kept intact (and
    // exercised by the simtest under `enabled = true`). TODO: move COMPUTE to an async worker
    // queue off the import critical path, then re-enable.
    if (!enabled) return staged;

    const block_atts = signed_block.block.body.attestations.constSlice();
    if (block_atts.len == 0) return staged;

    const validators = parent_state.validators.constSlice();

    // The block already passed verifySignatures upstream, so a decode failure here is a realistic
    // SSZ edge only — non-fatal: recover nothing (matches the spec wrapper's swallow-and-return).
    var container: types.TypeTwoMultiSignature = undefined;
    ssz.deserialize(types.TypeTwoMultiSignature, signed_block.proof.constSlice(), &container, allocator) catch {
        return staged;
    };
    defer container.deinit();

    // All PublicKey wrappers resolved in this call — kept alive through the split + aggregate
    // prover calls, freed once at the end (their handles are referenced by pks_per_message and the
    // per-merge child pubkey arrays).
    var pk_wrappers: std.ArrayList(xmss.PublicKey) = .empty;
    defer {
        for (pk_wrappers.items) |*w| w.deinit();
        pk_wrappers.deinit(allocator);
    }

    // Per-message pubkey layout the Type-2 was built against: one entry per body attestation in
    // order, then the proposer. Invariant per block — hoisted out of the per-attestation loop.
    const num_messages = block_atts.len + 1;
    const pks_per_message = try allocator.alloc([]*const xmss.HashSigPublicKey, num_messages);
    defer {
        for (pks_per_message) |s| if (s.len > 0) allocator.free(s);
        allocator.free(pks_per_message);
    }
    for (pks_per_message) |*s| s.* = &.{};

    for (block_atts, 0..) |att, i| {
        var vids = try types.aggregationBitsToValidatorIndices(&att.aggregation_bits, allocator);
        defer vids.deinit(allocator);
        const handles = try allocator.alloc(*const xmss.HashSigPublicKey, vids.items.len);
        for (vids.items, 0..) |vid, j| {
            if (vid >= validators.len) return staged; // malformed; recover nothing
            const pk = try xmss.PublicKey.fromBytes(validators[vid].getAttestationPubkey());
            try pk_wrappers.append(allocator, pk);
            handles[j] = pk.handle;
        }
        pks_per_message[i] = handles;
    }
    {
        const proposer_index: usize = @intCast(signed_block.block.proposer_index);
        if (proposer_index >= validators.len) return staged;
        const pk = try xmss.PublicKey.fromBytes(validators[proposer_index].getProposalPubkey());
        try pk_wrappers.append(allocator, pk);
        const handles = try allocator.alloc(*const xmss.HashSigPublicKey, 1);
        handles[0] = pk.handle;
        pks_per_message[block_atts.len] = handles;
    }

    // Only attestations whose target can still advance justification are worth a split.
    const justified = fork_choice.getLatestJustified();

    // Snapshot local partial Type-1 proofs per block-attestation data, cloned out under
    // signatures_mutex so the lock can be released before the prover runs. zeam's
    // AggregatedPayloadsMap is keyed by AttestationData (structurally hashed), so equal data shares
    // a key — the per-key list already groups all partials for that data.
    var snapshots = try allocator.alloc(std.ArrayList(TypeOneMultiSignature), block_atts.len);
    var snapshots_inited: usize = 0;
    defer {
        for (snapshots[0..snapshots_inited]) |*list| {
            for (list.items) |*p| p.deinit();
            list.deinit(allocator);
        }
        allocator.free(snapshots);
    }
    {
        fork_choice.signatures_mutex.lock();
        defer fork_choice.signatures_mutex.unlock();
        for (block_atts, 0..) |att, i| {
            var list: std.ArrayList(TypeOneMultiSignature) = .empty;
            if (fork_choice.latest_new_aggregated_payloads.get(att.data)) |stored_list| {
                for (stored_list.items) |stored| {
                    var clone: TypeOneMultiSignature = undefined;
                    try types.sszClone(allocator, TypeOneMultiSignature, stored.proof, &clone);
                    try list.append(allocator, clone);
                }
            }
            snapshots[i] = list;
            snapshots_inited = i + 1;
        }
    }

    for (block_atts, 0..) |att, i| {
        const data = att.data;
        // A target at or behind the justified checkpoint cannot move justification — skip.
        if (data.target.slot <= justified.slot) continue;

        var data_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.AttestationData, data, &data_root, allocator);

        const local_proofs = snapshots[i].items;

        // Coverage accumulator, seeded with the block component's participants. Selecting local
        // partials greedily against this union guarantees no validator appears in two children of
        // the aggregate call (which would break the merge).
        var covered = std.AutoHashMap(usize, void).init(allocator);
        defer covered.deinit();
        {
            var bvids = try types.aggregationBitsToValidatorIndices(&att.aggregation_bits, allocator);
            defer bvids.deinit(allocator);
            for (bvids.items) |v| try covered.put(v, {});
        }

        // Does the block component cover any validator not already in the local union? If not,
        // there is nothing to recover for this data. (local_union ⊇ block_participants check.)
        var local_union = std.AutoHashMap(usize, void).init(allocator);
        defer local_union.deinit();
        for (local_proofs) |proof| {
            var pvids = try types.aggregationBitsToValidatorIndices(&proof.participants, allocator);
            defer pvids.deinit(allocator);
            for (pvids.items) |v| try local_union.put(v, {});
        }
        var block_adds_new = false;
        {
            var bvids = try types.aggregationBitsToValidatorIndices(&att.aggregation_bits, allocator);
            defer bvids.deinit(allocator);
            for (bvids.items) |v| {
                if (!local_union.contains(v)) {
                    block_adds_new = true;
                    break;
                }
            }
        }
        if (!block_adds_new) continue;

        // Split this attestation's Type-1 out of the Type-2; restore participants from the block
        // attestation bits (split returns an empty participant set). Split matches the component by
        // message hash alone (no slot), which is unambiguous here: every component message in the
        // block's Type-2 is distinct — verifySignatures rejects duplicate attestation data roots and
        // the proposer's block_root, so no two components share a message hash.
        var block_t1 = try TypeOneMultiSignature.init(allocator);
        var block_t1_owned = true;
        defer if (block_t1_owned) block_t1.deinit();
        types.TypeTwoMultiSignature.splitByMessage(&container, pks_per_message, &data_root, &block_t1) catch continue;
        block_t1.participants.deinit();
        try types.sszClone(allocator, AggregationBits, att.aggregation_bits, &block_t1.participants);

        // Greedily select local partials whose participant set is FULLY DISJOINT from `covered`
        // (seeded with the block component, then grown per selection). A Type-1 proof is atomic —
        // we cannot take a subset of its signers — so a partial that merely OVERLAPS would place a
        // validator in two children of the aggregate call. Skipping partial overlaps keeps the
        // children truly disjoint, as the merge requires (the previous "adds any new validator"
        // rule did not: it unioned the whole overlapping set into `covered`). Cap the child count
        // (block component + partials) at MAX_AGGREGATE_CHILDREN so we never exceed MAX_RECURSIONS.
        var selected_idx: std.ArrayList(usize) = .empty;
        defer selected_idx.deinit(allocator);
        for (local_proofs, 0..) |proof, pi| {
            if (selected_idx.items.len + 1 >= MAX_AGGREGATE_CHILDREN) break;
            var pvids = try types.aggregationBitsToValidatorIndices(&proof.participants, allocator);
            defer pvids.deinit(allocator);
            if (pvids.items.len == 0) continue;
            var disjoint = true;
            for (pvids.items) |v| {
                if (covered.contains(v)) {
                    disjoint = false;
                    break;
                }
            }
            if (!disjoint) continue;
            try selected_idx.append(allocator, pi);
            for (pvids.items) |v| try covered.put(v, {});
        }

        var entry: StagedEntry = .{
            .data = data,
            .combined = undefined,
            .superseded = .empty,
        };

        if (selected_idx.items.len == 0) {
            // Nothing local to merge — use the split component as-is. Move ownership into the entry.
            entry.combined = block_t1;
            block_t1_owned = false;
        } else {
            // Build children = [block_t1, selected partials...] and their per-child pubkey handles,
            // then aggregate into one Type-1 (participants = union).
            const n_children = selected_idx.items.len + 1;
            const children = try allocator.alloc(TypeOneMultiSignature, n_children);
            defer allocator.free(children);
            const children_pks = try allocator.alloc([]*const xmss.HashSigPublicKey, n_children);
            defer {
                for (children_pks) |s| if (s.len > 0) allocator.free(s);
                allocator.free(children_pks);
            }
            for (children_pks) |*s| s.* = &.{};

            children[0] = block_t1;
            children_pks[0] = try resolveAttPubkeys(allocator, &pk_wrappers, validators, &block_t1.participants);
            for (selected_idx.items, 0..) |pi, k| {
                children[k + 1] = local_proofs[pi];
                children_pks[k + 1] = try resolveAttPubkeys(allocator, &pk_wrappers, validators, &local_proofs[pi].participants);
            }

            var combined = try TypeOneMultiSignature.init(allocator);
            errdefer combined.deinit();
            const no_raw_pks: []*const xmss.HashSigPublicKey = &.{};
            const no_raw_sigs: []*const xmss.HashSigSignature = &.{};
            TypeOneMultiSignature.aggregate(
                allocator,
                null,
                children,
                children_pks,
                no_raw_pks,
                no_raw_sigs,
                &data_root,
                data.slot,
                &combined,
            ) catch {
                combined.deinit();
                continue;
            };
            entry.combined = combined;
            // entry is not in `staged` yet, so the function-level `errdefer staged.deinit()` will
            // NOT free its superseded bits if a clone/append below fails — clean them up here.
            // (entry.combined aliases `combined`, freed by the errdefer above; not touched here.)
            errdefer {
                for (entry.superseded.items) |*p| p.deinit();
                entry.superseded.deinit(allocator);
            }

            // Record the superseded partials (their participant sets) so commit can drop them.
            for (selected_idx.items) |pi| {
                var bits: AggregationBits = undefined;
                try types.sszClone(allocator, AggregationBits, local_proofs[pi].participants, &bits);
                errdefer bits.deinit(); // free the in-flight clone if the append fails
                try entry.superseded.append(allocator, bits);
            }
        }

        staged.entries.append(allocator, entry) catch {
            entry.combined.deinit();
            for (entry.superseded.items) |*p| p.deinit();
            entry.superseded.deinit(allocator);
            return staged;
        };
    }

    return staged;
}

/// Resolve attestation pubkey handles for a participant bitfield into `pk_wrappers` (kept alive by
/// the caller). Returns an owned handle slice the caller frees.
fn resolveAttPubkeys(
    allocator: Allocator,
    pk_wrappers: *std.ArrayList(xmss.PublicKey),
    validators: []const types.Validator,
    participants: *const AggregationBits,
) ![]*const xmss.HashSigPublicKey {
    var vids = try types.aggregationBitsToValidatorIndices(participants, allocator);
    defer vids.deinit(allocator);
    const handles = try allocator.alloc(*const xmss.HashSigPublicKey, vids.items.len);
    errdefer allocator.free(handles);
    for (vids.items, 0..) |vid, j| {
        const pk = try xmss.PublicKey.fromBytes(validators[vid].getAttestationPubkey());
        try pk_wrappers.append(allocator, pk);
        handles[j] = pk.handle;
    }
    return handles;
}

/// COMMIT phase (infallible) — runs AFTER the fork-choice mutations succeed. Inserts each staged
/// combined proof into `latest_new_aggregated_payloads` and best-effort drops the partials it
/// superseded. Returns the recovered aggregates (owned by the caller) for the aggregator role to
/// gossip; on any internal failure it simply returns fewer aggregates (never errors), because
/// fork-choice weight already landed via the tracker and a rotation race here is benign.
///
/// `staged` is consumed (its combined proofs are moved out / freed).
pub fn deconstructCommit(
    allocator: Allocator,
    fork_choice: *ForkChoice,
    staged: *StagedDeconstruct,
) std.ArrayList(types.SignedAggregatedAttestation) {
    var aggregates: std.ArrayList(types.SignedAggregatedAttestation) = .empty;

    fork_choice.signatures_mutex.lock();
    defer fork_choice.signatures_mutex.unlock();

    for (staged.entries.items) |*entry| {
        // Best-effort: drop superseded partials from the live pool (a rotation between compute and
        // commit may have already moved some to `known` — leave those; the greedy set-cover at
        // build/aggregation time dedups redundant coverage anyway).
        if (entry.superseded.items.len > 0) {
            if (fork_choice.latest_new_aggregated_payloads.getPtr(entry.data)) |list_ptr| {
                var w: usize = 0;
                for (list_ptr.items) |*stored| {
                    var drop = false;
                    for (entry.superseded.items) |*sup| {
                        if (aggBitsEqual(&stored.proof.participants, sup)) {
                            drop = true;
                            break;
                        }
                    }
                    if (drop) {
                        // Free ALL owned fields, matching deinitAggregatedPayloadsList: a
                        // StoredAggregatedPayload owns its proof AND the two optional
                        // source-attribution bitfields. Freeing only proof leaked those bits on
                        // every superseded drop.
                        stored.proof.deinit();
                        if (stored.source_payload_participants) |*bits| bits.deinit();
                        if (stored.source_gossip_participants) |*bits| bits.deinit();
                    } else {
                        list_ptr.items[w] = stored.*;
                        w += 1;
                    }
                }
                list_ptr.shrinkRetainingCapacity(w);
            }
        }

        // Insert the combined proof (clone into the pool; keep one clone for the gossip aggregate).
        // Idempotent insert: always valid (a superset of the partials it merged).
        var pool_clone: TypeOneMultiSignature = undefined;
        types.sszClone(allocator, TypeOneMultiSignature, entry.combined, &pool_clone) catch continue;
        const gop = fork_choice.latest_new_aggregated_payloads.getOrPut(entry.data) catch {
            pool_clone.deinit();
            continue;
        };
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        gop.value_ptr.append(allocator, .{
            .slot = entry.data.slot,
            .proof = pool_clone,
        }) catch {
            pool_clone.deinit();
            continue;
        };

        // Move the combined proof into the returned aggregate (transfer ownership; the staged entry
        // no longer owns it — mark by leaving a fresh empty so StagedDeconstruct.deinit is safe).
        var gossip_proof = entry.combined;
        entry.combined = TypeOneMultiSignature.init(allocator) catch {
            // Could not re-init a placeholder; keep the proof in the entry (deinit'd later) and skip
            // the aggregate. gossip_proof and entry.combined alias — do NOT double free.
            continue;
        };
        aggregates.append(allocator, .{ .data = entry.data, .proof = gossip_proof }) catch {
            gossip_proof.deinit();
            continue;
        };
    }

    return aggregates;
}
