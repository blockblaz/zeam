//! Bounded set of permanently-invalid block roots.
//!
//! See `BeamChain.invalid_block_roots` for the call-site contract and the
//! commit log for the slot=13 devnet trace this defends against.
//!
//! Block validity is a deterministic predicate over the block's bytes
//! (`hash_tree_root(block)` → unique content). Once a verifier returns a
//! deterministic-failure verdict (signature deserialize/verify fail,
//! structural mismatch, proposer-sig fail) for root R, refetching R will
//! always reproduce the same verdict — caching the verdict avoids
//! re-running the full verify on every gossip / blocks_by_root delivery.
//!
//! Spec-safe because:
//!   * the spec defines block validity as `f(block_bytes)`; this cache is a
//!     memoization of f
//!   * fork-choice (LMD-GHOST) only chooses between *valid* heads; an
//!     invalid block can never be on a future canonical chain, so blacklisting
//!     does not interfere with re-orgs
//!
//! Caller must ONLY insert for deterministic failures:
//!   * AggregationError.InvalidAggregateSignature
//!   * StateTransitionError.InvalidBlockSignatures
//!   * StateTransitionError.InvalidValidatorId
//!   * BlockProcessingError.InvalidSignatureGroups
//!   * BlockProcessingError.DuplicateAttestationData
//!   * BlockProcessingError.TooManyAttestationData
//!   * HashSigError.InvalidSignature / VerificationFailed (proposer sig)
//!
//! Do NOT insert for state-dependent or transient errors:
//!   * InvalidPostState (our pre-state may be wrong; a re-org through a
//!     different ancestor could legitimately re-enable the block)
//!   * MissingPreState / MissingState (transient — state may arrive later)
//!   * UnknownParentBlock / FutureSlot (transient — block ordering)

const std = @import("std");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");

pub const InvalidBlockSet = struct {
    /// O(1) membership test.
    roots: std.AutoHashMap(types.Root, void),
    /// FIFO eviction order. When `roots.count() == max_entries` we drop the
    /// front of this queue before inserting the new root, so memory is
    /// bounded over the node's lifetime.
    insertion_order: std.ArrayListUnmanaged(types.Root),
    /// Single-writer (chain-worker) + multi-reader (libxev gossip/orphan
    /// paths). Held only inside the cache methods; never co-held with any
    /// other chain lock.
    mutex: zeam_utils.SyncMutex = .{},
    max_entries: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) Self {
        return .{
            .roots = std.AutoHashMap(types.Root, void).init(allocator),
            .insertion_order = .empty,
            .max_entries = max_entries,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.roots.deinit();
        self.insertion_order.deinit(self.allocator);
    }

    /// Returns true if `root` was newly inserted, false if it was already
    /// present (in which case `insertion_order` is left untouched — we
    /// don't refresh recency on duplicate marks). On OOM the root is
    /// silently dropped: the worst case is a missed dedup, not a
    /// correctness bug.
    pub fn mark(self: *Self, root: types.Root) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const gop = self.roots.getOrPut(root) catch return false;
        if (gop.found_existing) return false;

        // First time we've seen this root. Enforce the cap before
        // appending so the queue + map sizes stay in lockstep.
        if (self.roots.count() > self.max_entries and self.insertion_order.items.len > 0) {
            const evicted = self.insertion_order.orderedRemove(0);
            // Don't remove `root` itself even if FIFO points at it — the
            // caller is mid-insert. Skip eviction in that pathological
            // case (max_entries=0); cache stays empty.
            if (!std.mem.eql(u8, &evicted, &root)) {
                _ = self.roots.remove(evicted);
            } else {
                _ = self.roots.remove(root);
                return false;
            }
        }
        self.insertion_order.append(self.allocator, root) catch {
            // Roll back the map insert so we don't desync.
            _ = self.roots.remove(root);
            return false;
        };
        return true;
    }

    pub fn contains(self: *Self, root: types.Root) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.roots.contains(root);
    }

    pub fn count(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.roots.count();
    }
};

test "InvalidBlockSet — basic mark + contains" {
    var set = InvalidBlockSet.init(std.testing.allocator, 4);
    defer set.deinit();

    const r1: types.Root = [_]u8{1} ** 32;
    const r2: types.Root = [_]u8{2} ** 32;

    try std.testing.expect(!set.contains(r1));
    try std.testing.expect(set.mark(r1));
    try std.testing.expect(set.contains(r1));
    // Duplicate mark is a no-op.
    try std.testing.expect(!set.mark(r1));
    try std.testing.expectEqual(@as(usize, 1), set.count());

    try std.testing.expect(set.mark(r2));
    try std.testing.expectEqual(@as(usize, 2), set.count());
}

test "InvalidBlockSet — FIFO eviction at cap" {
    var set = InvalidBlockSet.init(std.testing.allocator, 2);
    defer set.deinit();

    const r1: types.Root = [_]u8{1} ** 32;
    const r2: types.Root = [_]u8{2} ** 32;
    const r3: types.Root = [_]u8{3} ** 32;

    _ = set.mark(r1);
    _ = set.mark(r2);
    _ = set.mark(r3); // evicts r1
    try std.testing.expect(!set.contains(r1));
    try std.testing.expect(set.contains(r2));
    try std.testing.expect(set.contains(r3));
    try std.testing.expectEqual(@as(usize, 2), set.count());
}
