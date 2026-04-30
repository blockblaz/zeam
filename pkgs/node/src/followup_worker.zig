//! Followup worker thread (issue #786 follow-up: requirement 6 + 7).
//!
//! `chain.onBlockFollowup` runs on the gossip / libxev thread today, blocking
//! the next gossip message until events are emitted, finalization checked,
//! and pruning runs. None of that work is on the consensus-critical path —
//! the block is already imported by the time followup fires. Push it onto
//! a dedicated worker thread so the gossip thread can return immediately.
//!
//! Requirement 7 ("remove onBlockFollowup from any backfilling operations")
//! is enforced at the caller side: backfill paths simply do not enqueue
//! followup jobs.

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");

/// A single followup job. Produced by `chain.onBlock` callers, consumed by
/// the worker.
pub const FollowupJob = struct {
    /// Whether this followup should also run forkchoice pruning. Mirrors the
    /// `pruneForkchoice` argument the inline path uses today.
    prune_forkchoice: bool,
    /// Optional snapshot of the imported block. Owned by the queue entry —
    /// freed by the worker after dispatch. `null` for paths that don't need
    /// the block ref (most do not).
    signed_block: ?*types.SignedBlock,
};

/// Bounded MPSC queue + worker thread.
pub const FollowupWorker = struct {
    allocator: Allocator,
    logger: zeam_utils.ModuleLogger,

    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    queue: std.ArrayList(FollowupJob) = .empty,
    /// Set on shutdown; worker drains then exits.
    shutdown: bool = false,
    /// Pending allocator-owned block clones to free; freed in `deinit` if not
    /// drained.
    thread: ?std.Thread = null,

    /// Callback into chain layer. The worker invokes this for each dequeued
    /// job. The chain layer is responsible for taking the appropriate
    /// per-resource locks (events_lock for last_emitted_*, states_lock /
    /// finalization_lock for prune coordination).
    dispatch_ctx: ?*anyopaque = null,
    dispatch_fn: ?DispatchFn = null,

    pub const DispatchFn = *const fn (ctx: *anyopaque, job: FollowupJob) void;

    const Self = @This();

    pub fn init(allocator: Allocator, logger: zeam_utils.ModuleLogger) Self {
        return .{
            .allocator = allocator,
            .logger = logger,
        };
    }

    /// Wire the dispatch callback and spawn the worker thread. Must be called
    /// after the chain (and its locks) are fully initialised but before any
    /// `enqueue` call. Idempotent: a second call panics.
    pub fn start(self: *Self, dispatch_ctx: *anyopaque, dispatch_fn: DispatchFn) !void {
        if (self.thread != null) @panic("FollowupWorker.start called twice");
        self.dispatch_ctx = dispatch_ctx;
        self.dispatch_fn = dispatch_fn;
        self.thread = try std.Thread.spawn(.{ .allocator = self.allocator }, runLoop, .{self});
    }

    /// Signal shutdown, wake the worker, and join. Drains any remaining jobs
    /// before returning so finalization-side resources are freed.
    pub fn deinit(self: *Self) void {
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.shutdown = true;
            self.cond.signal();
        }
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        // Free any remaining queue entries' owned clones.
        for (self.queue.items) |job| {
            if (job.signed_block) |sb| {
                sb.deinit();
                self.allocator.destroy(sb);
            }
        }
        self.queue.deinit(self.allocator);
    }

    /// Enqueue a followup job. Non-blocking. Caller transfers ownership of
    /// `job.signed_block` (if any) to the worker.
    pub fn enqueue(self: *Self, job: FollowupJob) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutdown) {
            // Free any owned clone — we won't process this job.
            if (job.signed_block) |sb| {
                sb.deinit();
                self.allocator.destroy(sb);
            }
            return;
        }
        try self.queue.append(self.allocator, job);
        self.cond.signal();
    }

    fn runLoop(self: *Self) void {
        while (true) {
            var job: FollowupJob = undefined;
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                while (self.queue.items.len == 0 and !self.shutdown) {
                    self.cond.wait(&self.mutex);
                }
                if (self.queue.items.len == 0 and self.shutdown) return;
                job = self.queue.orderedRemove(0);
            }

            // Dispatch outside the queue lock so chain-side locks (events_lock,
            // states_lock, etc.) don't nest under it.
            if (self.dispatch_fn) |df| {
                if (self.dispatch_ctx) |ctx| {
                    df(ctx, job);
                }
            }

            // Free the worker-owned clone now that dispatch is done.
            if (job.signed_block) |sb| {
                sb.deinit();
                self.allocator.destroy(sb);
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests (issue #786 follow-up: lock-invariant unit tests).
//
// These exercise the queue + worker lifecycle in isolation. They use
// `signed_block = null` so the SignedBlock free path is not exercised here;
// the worker's free-on-shutdown branch is covered with a sentinel ctx that
// only counts dispatches.
// ---------------------------------------------------------------------------

const testing = std.testing;

const TestCtx = struct {
    dispatched: std.atomic.Value(u64) = .init(0),
    last_prune: std.atomic.Value(bool) = .init(false),

    fn dispatch(ctx_opaque: *anyopaque, job: FollowupJob) void {
        const self: *TestCtx = @ptrCast(@alignCast(ctx_opaque));
        _ = self.dispatched.fetchAdd(1, .seq_cst);
        self.last_prune.store(job.prune_forkchoice, .seq_cst);
    }
};

fn testLogger() zeam_utils.ModuleLogger {
    const Holder = struct {
        var cfg = zeam_utils.getTestLoggerConfig();
    };
    return Holder.cfg.logger(.node);
}

test "FollowupWorker dispatches enqueued jobs in order" {
    var worker = FollowupWorker.init(testing.allocator, testLogger());
    defer worker.deinit();

    var ctx = TestCtx{};
    try worker.start(&ctx, TestCtx.dispatch);

    try worker.enqueue(.{ .prune_forkchoice = false, .signed_block = null });
    try worker.enqueue(.{ .prune_forkchoice = true, .signed_block = null });
    try worker.enqueue(.{ .prune_forkchoice = false, .signed_block = null });

    // Spin until the worker has drained all 3 jobs (or timeout).
    const deadline_ms: u64 = 2000;
    const step_ms: u64 = 5;
    var waited: u64 = 0;
    while (ctx.dispatched.load(.seq_cst) < 3 and waited < deadline_ms) {
        std.Thread.sleep(step_ms * std.time.ns_per_ms);
        waited += step_ms;
    }
    try testing.expectEqual(@as(u64, 3), ctx.dispatched.load(.seq_cst));
    // Last enqueue's prune flag is false; FIFO order means last_prune ends up false.
    try testing.expectEqual(false, ctx.last_prune.load(.seq_cst));
}

test "FollowupWorker drops jobs after shutdown without leaking" {
    var worker = FollowupWorker.init(testing.allocator, testLogger());
    var ctx = TestCtx{};
    try worker.start(&ctx, TestCtx.dispatch);
    worker.deinit();

    // Post-shutdown enqueue must be silently dropped (signed_block is null
    // here so no clone-free path is taken; the branch is still exercised).
    try worker.enqueue(.{ .prune_forkchoice = false, .signed_block = null });
    try testing.expectEqual(@as(u64, 0), ctx.dispatched.load(.seq_cst));
}

test "FollowupWorker deinit drains undispatched jobs (no worker started)" {
    // No `start` call: worker thread never runs. Inject a job directly so
    // that deinit exercises the queue-drain branch.
    var worker = FollowupWorker.init(testing.allocator, testLogger());
    try worker.queue.append(testing.allocator, .{
        .prune_forkchoice = true,
        .signed_block = null,
    });
    worker.deinit();
}
