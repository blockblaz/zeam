//! Network-fetch worker thread (issue #786 req. 8).
//!
//! Today every gossip block / RPC backfill path that discovers a missing
//! root issues `fetchBlockByRoots(...)` synchronously on the gossip thread
//! itself. The call ends up in the libp2p bridge, which forwards a
//! blocks_by_root request to a peer. The gossip thread blocks for the
//! duration of the network send.
//!
//! Same shape problem as `onBlockFollowup`: the fetch is not on the
//! consensus-critical path — the imported block is already settled by the
//! time we discover a missing attestation head root. Push the fetch onto
//! a worker thread so the gossip thread returns immediately.
//!
//! This module is the **scaffold** for that worker. The queue + thread are
//! wired into `BeamNode.init` / `deinit`; the actual migration of
//! `fetchBlockByRoots` callsites to `enqueue` happens in a follow-up
//! iteration once the per-resource locks settle. The worker is exercised
//! today only for the "sweep timed-out RPC requests" retry path, which
//! is the smallest call site to migrate first (single retry source, no
//! depth tracking subtleties).
//!
//! Design choices:
//! - MPSC queue, identical shape to `FollowupWorker`. The producer side
//!   is any thread that wants to fire-and-forget a fetch; the consumer
//!   is a single dedicated thread that drains the queue and dispatches
//!   one job at a time. Network-side rate limiting (bounded peer slots)
//!   lives below the worker, in the libp2p bridge.
//! - Owned roots: each job holds a heap-allocated `[]types.Root`. The
//!   worker frees the slice after dispatch.
//! - Bounded by allocator pressure rather than queue length. If
//!   sustained queue growth becomes a concern (e.g. partition + flood),
//!   add a length cap + drop-on-full policy.

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");

pub const NetFetchJob = struct {
    /// Owned slice of block roots to fetch in a single
    /// `blocks_by_root` request. Worker frees on dispatch.
    roots: []types.Root,
    /// Recursion depth used by the existing fetch logic to decide whether
    /// to chase parent chains. Forwarded as-is to `fetchBlockByRoots`.
    depth: u32,
};

pub const NetFetchWorker = struct {
    allocator: Allocator,
    logger: zeam_utils.ModuleLogger,

    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    queue: std.ArrayList(NetFetchJob) = .empty,
    shutdown: bool = false,
    thread: ?std.Thread = null,

    dispatch_ctx: ?*anyopaque = null,
    dispatch_fn: ?DispatchFn = null,

    /// Worker dispatch callback. Receives an owned-roots job; the worker
    /// frees the roots slice after the callback returns.
    pub const DispatchFn = *const fn (ctx: *anyopaque, roots: []const types.Root, depth: u32) void;

    const Self = @This();

    pub fn init(allocator: Allocator, logger: zeam_utils.ModuleLogger) Self {
        return .{
            .allocator = allocator,
            .logger = logger,
        };
    }

    pub fn start(self: *Self, dispatch_ctx: *anyopaque, dispatch_fn: DispatchFn) !void {
        if (self.thread != null) @panic("NetFetchWorker.start called twice");
        self.dispatch_ctx = dispatch_ctx;
        self.dispatch_fn = dispatch_fn;
        self.thread = try std.Thread.spawn(.{ .allocator = self.allocator }, runLoop, .{self});
    }

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
        // Free any remaining queue entries' owned roots.
        for (self.queue.items) |job| {
            self.allocator.free(job.roots);
        }
        self.queue.deinit(self.allocator);
    }

    /// Enqueue a fetch job. Caller transfers ownership of `roots` to the
    /// worker. Non-blocking. On worker shutdown, `roots` is freed and the
    /// job is dropped silently — caller must treat enqueue as
    /// fire-and-forget.
    pub fn enqueue(self: *Self, roots: []types.Root, depth: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutdown) {
            self.allocator.free(roots);
            return;
        }
        try self.queue.append(self.allocator, .{ .roots = roots, .depth = depth });
        self.cond.signal();
    }

    fn runLoop(self: *Self) void {
        while (true) {
            var job: NetFetchJob = undefined;
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                while (self.queue.items.len == 0 and !self.shutdown) {
                    self.cond.wait(&self.mutex);
                }
                if (self.queue.items.len == 0 and self.shutdown) return;
                job = self.queue.orderedRemove(0);
            }

            // Dispatch outside the queue lock so chain/network locks taken
            // by the dispatch callback don't nest under it.
            if (self.dispatch_fn) |df| {
                if (self.dispatch_ctx) |ctx| {
                    df(ctx, job.roots, job.depth);
                }
            }
            self.allocator.free(job.roots);
        }
    }
};
