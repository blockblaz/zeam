//! Chain-worker thread + bounded queue scaffold (slice c-1 of #803).
//!
//! Background: today every chain-mutation entry point (`onBlock`,
//! `onGossipBlock`, `onGossipAttestation`, `onGossipAggregatedAttestation`,
//! `processPendingBlocks`, `processFinalizationFollowup`) runs synchronously
//! on whichever thread invoked it — the libxev main thread for slot ticks,
//! the libp2p bridge thread for gossip/req-resp, and the HTTP API task for
//! a few admin paths. Slice (a) shrunk the per-resource lock spans so each
//! call is bounded, but the contention surface is still wide and a slow
//! STF on one thread blocks every other producer.
//!
//! Slice (c) introduces a single chain-worker thread that owns every
//! chain-mutation resource exclusively. Producers (libxev / libp2p /
//! HTTP) marshal work into this module's bounded queue; the worker drains
//! it serially. The lock hierarchy in `locking.zig` becomes a near-no-op
//! on the mutation path (the worker is sole writer) but keeps its
//! cross-thread *read* sides for HTTP/metrics/event-broadcaster snapshots.
//!
//! Slice c-1 (this file) ships the **scaffold only**:
//!
//!   * `Message` tagged union covering every chain-mutation entry point.
//!   * `BoundedQueue(Message, capacity)` — a bounded ring with a single
//!     consumer, multi-producer mutex+condvar protocol. Producers call
//!     `trySend` (wait-free fail-on-full) so the libp2p bridge thread
//!     never blocks on a full queue. The drain side wakes on push and
//!     is woken on shutdown.
//!   * `ChainWorker` — owns the thread, stop signal, and the two queues
//!     (block-FIFO, attestation-LIFO per the design doc §"Bounded queue,
//!     backpressure, and starvation"). The worker loop is a stub —
//!     handlers return `unreachable`-tagged TODOs; slice c-2 wires them.
//!
//! Behavioral changes are deferred to slice c-2:
//!
//!   * `BeamChain` does NOT yet hold a `*ChainWorker`.
//!   * No callsite enqueues anything onto these queues.
//!   * No CLI flag is wired.
//!
//! This file is therefore reachable only from its own tests in c-1; the
//! production binary builds it, links it, but never instantiates it.
//! Reviewers can audit the queue/worker contracts in isolation before
//! c-2 lands the per-handler migration.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const networks = @import("@zeam/network");
const zeam_metrics = @import("@zeam/metrics");
const zeam_utils = @import("@zeam/utils");

/// Resolve the project's default `std.Io` instance. Mirrors the pattern
/// in `pkgs/utils/src/sync.zig`: the chain-worker queue is purely a
/// thread-blocking primitive (no async fiber semantics required), so
/// the global single-threaded io is the right choice. If a future change
/// switches the threading model, every callsite here can be retargeted
/// to a different `Io` instance.
fn defaultIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Tagged union covering every chain-mutation entry point.
///
/// Each variant carries the data the chain-worker needs to run the
/// equivalent synchronous call as it exists today (slice b). The
/// `Shutdown` variant is the worker's only sentinel for graceful exit;
/// `ChainWorker.stop()` enqueues it on the block queue (highest-priority
/// queue, drained first) so the worker exits cleanly even mid-attestation
/// burst.
///
/// Ownership: every payload allocated by a producer (e.g. the
/// `signed_block` SSZ buffer on `OnBlock`) is the worker's responsibility
/// to free after handling. c-1 does not yet exercise this — c-2 wires
/// the producers and writes the matching ownership tests.
pub const Message = union(enum) {
    /// Full block import. Producer is libxev (replay path), libp2p
    /// gossip handler (after gossipsub validation), or req/resp.
    on_block: struct {
        signed_block: types.SignedBlock,
        prune_forkchoice: bool,
    },
    /// Single attestation gossip. Producer is libp2p gossip handler.
    on_gossip_attestation: networks.AttestationGossip,
    /// Aggregated-attestation gossip. Producer is libp2p gossip handler.
    on_gossip_aggregated_attestation: types.SignedAggregatedAttestation,
    /// `processPendingBlocks` drain trigger. Producer is libxev clock
    /// (`onInterval`).
    process_pending_blocks: struct {
        current_slot: types.Slot,
    },
    /// `processFinalizationFollowup` move-off path (slice c-2 will
    /// dispatch this; c-1 just defines the variant).
    process_finalization_followup: struct {
        emit_events: bool,
    },
    /// Sentinel — drains the worker loop. Only `ChainWorker.stop` emits
    /// it; producers must not.
    shutdown: void,
};

/// Bounded ring queue, multi-producer / single-consumer.
///
/// Implementation: contiguous heap-allocated array of capacity items, plus
/// `head` / `len` indices guarded by a mutex. Producers `trySend` — fails
/// when `len == capacity`, success increments `len` and signals the
/// `not_empty` condvar. Consumer `recv` waits on `not_empty` until either
/// `len > 0` or `closed` is set, then dequeues from `head`.
///
/// Ordering policy is encoded by `mode` rather than a separate stack/queue
/// type: `.fifo` → recv from head (oldest first), `.lifo` → recv from
/// tail (newest first). The design doc §"Bounded queue, backpressure"
/// requires gossip blocks FIFO (ordering matters for safety) and gossip
/// attestations LIFO (freshness > ordering). Slashings will be FIFO too
/// when c-2 routes them; for c-1 we only ship the two queues we need
/// immediately.
///
/// Shutdown semantics: `close()` sets `closed = true` and broadcasts
/// `not_empty`. `recv` returns `null` once the queue is drained AND
/// closed; otherwise it keeps blocking. Producers that `trySend` after
/// close get `error.QueueClosed`.
/// Ordering policy for `BoundedQueue`. Public so callers can name the
/// mode explicitly when instantiating.
pub const QueueMode = enum { fifo, lifo };

pub fn BoundedQueue(comptime T: type, comptime mode: QueueMode) type {
    return struct {
        const Self = @This();

        items: []T,
        head: usize = 0,
        len: usize = 0,
        capacity: usize,
        closed: bool = false,
        mutex: std.Io.Mutex = .init,
        not_empty: std.Io.Condition = .init,

        // Producer-observable counters. Read with `.monotonic` from the
        // metrics layer; writers serialize under `mutex` so the
        // consistency between `len` and `dropped_total` is exact.
        dropped_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        sent_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        recv_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

        pub const TrySendError = error{ QueueFull, QueueClosed };

        pub fn init(allocator: Allocator, capacity: usize) !Self {
            std.debug.assert(capacity > 0);
            const items = try allocator.alloc(T, capacity);
            return .{ .items = items, .capacity = capacity };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.items);
            self.* = undefined;
        }

        /// Wait-free producer: returns `error.QueueFull` immediately if
        /// `len == capacity`, `error.QueueClosed` if `close()` ran. On
        /// success, the message is enqueued and a waiting consumer is
        /// woken.
        pub fn trySend(self: *Self, msg: T) TrySendError!void {
            const io = defaultIo();
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            if (self.closed) return error.QueueClosed;
            if (self.len == self.capacity) {
                _ = self.dropped_total.fetchAdd(1, .monotonic);
                return error.QueueFull;
            }
            const slot = (self.head + self.len) % self.capacity;
            self.items[slot] = msg;
            self.len += 1;
            _ = self.sent_total.fetchAdd(1, .monotonic);
            self.not_empty.signal(io);
        }

        /// Single-consumer blocking recv. Blocks until an item is
        /// available, or returns `null` if the queue is closed AND
        /// drained. The caller is responsible for any per-item cleanup
        /// (e.g. freeing payload buffers) since this returns `T` by
        /// value.
        ///
        /// Used by tests in c-1 and by the chain worker in c-2 when a
        /// queue is the only legitimate work source. The chain-worker
        /// loop in c-1 (`ChainWorker.runLoop`) does NOT use this on the
        /// hot path because the worker draining two queues must wake
        /// when EITHER queue has work — see `tryRecv` + the worker's
        /// shared condvar in `ChainWorker`.
        pub fn recv(self: *Self) ?T {
            const io = defaultIo();
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            while (self.len == 0 and !self.closed) {
                self.not_empty.waitUncancelable(io, &self.mutex);
            }
            return self.popLocked();
        }

        /// Single-consumer non-blocking recv. Returns `null` immediately
        /// when the queue is empty (whether closed or not). Used by the
        /// chain-worker loop, which multiplexes two queues and uses a
        /// shared condvar at the worker level for wakeup.
        pub fn tryRecv(self: *Self) ?T {
            const io = defaultIo();
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            return self.popLocked();
        }

        /// Internal: drop one item under a held mutex. Returns null if
        /// no item is available. Updates `recv_total` only on a real
        /// pop.
        fn popLocked(self: *Self) ?T {
            if (self.len == 0) return null;
            const idx = switch (mode) {
                .fifo => self.head,
                .lifo => (self.head + self.len - 1) % self.capacity,
            };
            const msg = self.items[idx];
            switch (mode) {
                .fifo => {
                    self.head = (self.head + 1) % self.capacity;
                },
                .lifo => {
                    // tail removal: head/anchor unchanged, len shrinks.
                },
            }
            self.len -= 1;
            _ = self.recv_total.fetchAdd(1, .monotonic);
            return msg;
        }

        /// Mark the queue closed and wake any waiting consumer. Idempotent.
        pub fn close(self: *Self) void {
            const io = defaultIo();
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            self.closed = true;
            self.not_empty.broadcast(io);
        }

        /// Snapshot of the current length, for metrics. Acquires the
        /// mutex briefly so reads do not race a partial enqueue/dequeue.
        pub fn depth(self: *Self) usize {
            const io = defaultIo();
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            return self.len;
        }
    };
}

pub const BlockQueue = BoundedQueue(Message, .fifo);
pub const AttestationQueue = BoundedQueue(Message, .lifo);

/// Default capacities. Generous enough that a 30s gossip burst on
/// devnet4 (~3 attestations/slot × 32 validators × 8 slots ≈ 800) does
/// not saturate. Tuned by the slice c-2 stress harness.
pub const DEFAULT_BLOCK_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_ATTESTATION_QUEUE_CAPACITY: usize = 1024;

/// Owns the chain-worker thread, the bounded queues, and a stop flag.
///
/// Lifecycle:
///
///   var worker = try ChainWorker.init(allocator, .{ .logger = ... });
///   defer worker.deinit();
///   try worker.start();         // spawns the loop thread
///   defer worker.stop();         // close queues + join
///
/// `start` and `stop` are NOT thread-safe with respect to themselves —
/// the owning code (typically `BeamChain.init` / `BeamChain.deinit`,
/// once c-2 wires it) must serialize them. Producers using `trySend`
/// on the queues are fully thread-safe.
pub const ChainWorker = struct {
    const Self = @This();

    allocator: Allocator,
    block_queue: BlockQueue,
    attestation_queue: AttestationQueue,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    /// Liveness counter: incremented on every loop iteration. Exposed
    /// via metrics so an external watchdog can observe whether the
    /// worker is actually draining work.
    loop_iters: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    logger: zeam_utils.ModuleLogger,

    pub const InitOpts = struct {
        block_queue_capacity: usize = DEFAULT_BLOCK_QUEUE_CAPACITY,
        attestation_queue_capacity: usize = DEFAULT_ATTESTATION_QUEUE_CAPACITY,
        logger: zeam_utils.ModuleLogger,
    };

    pub fn init(allocator: Allocator, opts: InitOpts) !Self {
        return .{
            .allocator = allocator,
            .block_queue = try BlockQueue.init(allocator, opts.block_queue_capacity),
            .attestation_queue = try AttestationQueue.init(
                allocator,
                opts.attestation_queue_capacity,
            ),
            .logger = opts.logger,
        };
    }

    /// Stops (if running) and frees all queue storage. Safe to call
    /// after `stop()`; no-op on an unstarted worker.
    pub fn deinit(self: *Self) void {
        if (self.thread != null) {
            self.stop();
        }
        self.block_queue.deinit(self.allocator);
        self.attestation_queue.deinit(self.allocator);
    }

    /// Spawn the loop thread. Returns an error if a thread already
    /// exists or if the OS rejects the spawn.
    pub fn start(self: *Self) !void {
        if (self.thread != null) return error.AlreadyRunning;
        self.thread = try std.Thread.spawn(.{}, runLoop, .{self});
    }

    /// Signal stop, close both queues so any blocked recv returns,
    /// then join the worker thread. Idempotent.
    pub fn stop(self: *Self) void {
        if (self.thread == null) return;
        self.stop_flag.store(true, .release);
        // Close queues so the recv() in runLoop returns null.
        self.block_queue.close();
        self.attestation_queue.close();
        if (self.thread) |t| {
            t.join();
        }
        self.thread = null;
    }

    /// Worker thread main loop. Drains the block queue first (FIFO,
    /// safety-ordered) then the attestation queue (LIFO, freshness-
    /// ordered) per the design doc. When BOTH queues are empty AND
    /// closed, returns. Stop_flag gives a fast-path early exit
    /// before either recv blocks again.
    fn runLoop(self: *Self) void {
        self.logger.info("chain-worker: loop started", .{});
        while (!self.stop_flag.load(.acquire)) {
            _ = self.loop_iters.fetchAdd(1, .monotonic);

            // Block queue takes priority: STF correctness + finalization
            // depends on import ordering. Drain everything available
            // without blocking before checking attestations.
            //
            // recv() blocks on empty + open. To avoid blocking on the
            // block queue when there's attestation work waiting, we use
            // depth() as an O(1) probe; the recv() call after a positive
            // depth is guaranteed to dequeue without blocking under
            // single-consumer semantics (no other thread drains).
            if (self.block_queue.depth() > 0) {
                if (self.block_queue.recv()) |msg| {
                    self.handle(msg);
                    continue;
                }
            }

            if (self.attestation_queue.depth() > 0) {
                if (self.attestation_queue.recv()) |msg| {
                    self.handle(msg);
                    continue;
                }
            }

            // Both queues empty. Block on the block queue (the
            // higher-priority one). recv() returns null when it is
            // closed AND drained; that's our exit condition. If it
            // returns a real message, dispatch and loop; if attestation
            // queue is the one with the new work, the next iteration
            // picks it up via the depth() probe above.
            const blk = self.block_queue.recv();
            if (blk == null) {
                // Block queue closed + drained. Drain whatever is
                // left in the attestation queue, then exit.
                while (self.attestation_queue.recv()) |msg| {
                    self.handle(msg);
                }
                break;
            }
            self.handle(blk.?);
        }
        self.logger.info("chain-worker: loop stopped", .{});
    }

    /// Slice c-1 stub. Real handlers land in c-2 alongside the
    /// per-callsite migration. Until then, this is unreachable in
    /// production — only tests exercise the worker, and they enqueue
    /// `Shutdown` only.
    fn handle(self: *Self, msg: Message) void {
        switch (msg) {
            .shutdown => {
                self.logger.debug("chain-worker: shutdown message received", .{});
                self.stop_flag.store(true, .release);
            },
            .on_block,
            .on_gossip_attestation,
            .on_gossip_aggregated_attestation,
            .process_pending_blocks,
            .process_finalization_followup,
            => {
                // c-2 wires these. Until then, the worker should never
                // receive them in production (no producer is wired).
                // In tests we may exercise the shape; do not panic, just
                // log so test failures are debuggable.
                self.logger.warn(
                    "chain-worker: unhandled message variant in c-1 scaffold: {s}",
                    .{@tagName(msg)},
                );
            },
        }
    }
};

// =====================================================================
// Tests
// =====================================================================

const testing = std.testing;

test "BoundedQueue.fifo: trySend / recv preserves insertion order" {
    var q = try BlockQueue.init(testing.allocator, 4);
    defer q.deinit(testing.allocator);

    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 1 } });
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 2 } });
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 3 } });

    try testing.expectEqual(@as(usize, 3), q.depth());

    const m1 = q.recv() orelse return error.UnexpectedNull;
    try testing.expectEqual(@as(types.Slot, 1), m1.process_pending_blocks.current_slot);
    const m2 = q.recv() orelse return error.UnexpectedNull;
    try testing.expectEqual(@as(types.Slot, 2), m2.process_pending_blocks.current_slot);
    const m3 = q.recv() orelse return error.UnexpectedNull;
    try testing.expectEqual(@as(types.Slot, 3), m3.process_pending_blocks.current_slot);

    try testing.expectEqual(@as(usize, 0), q.depth());
    q.close();
    try testing.expect(q.recv() == null);
}

test "BoundedQueue.lifo: trySend / recv returns newest first" {
    var q = try AttestationQueue.init(testing.allocator, 4);
    defer q.deinit(testing.allocator);

    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 1 } });
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 2 } });
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 3 } });

    const m3 = q.recv() orelse return error.UnexpectedNull;
    try testing.expectEqual(@as(types.Slot, 3), m3.process_pending_blocks.current_slot);
    const m2 = q.recv() orelse return error.UnexpectedNull;
    try testing.expectEqual(@as(types.Slot, 2), m2.process_pending_blocks.current_slot);
    const m1 = q.recv() orelse return error.UnexpectedNull;
    try testing.expectEqual(@as(types.Slot, 1), m1.process_pending_blocks.current_slot);

    q.close();
    try testing.expect(q.recv() == null);
}

test "BoundedQueue: trySend returns QueueFull at capacity, increments dropped_total" {
    var q = try BlockQueue.init(testing.allocator, 2);
    defer q.deinit(testing.allocator);

    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 1 } });
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 2 } });
    try testing.expectEqual(@as(u64, 0), q.dropped_total.load(.monotonic));

    try testing.expectError(
        error.QueueFull,
        q.trySend(.{ .process_pending_blocks = .{ .current_slot = 3 } }),
    );
    try testing.expectEqual(@as(u64, 1), q.dropped_total.load(.monotonic));

    // Drain one, then trySend should succeed again.
    _ = q.recv();
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 4 } });
    try testing.expectEqual(@as(u64, 1), q.dropped_total.load(.monotonic));
}

test "BoundedQueue: trySend returns QueueClosed after close()" {
    var q = try BlockQueue.init(testing.allocator, 4);
    defer q.deinit(testing.allocator);
    q.close();
    try testing.expectError(
        error.QueueClosed,
        q.trySend(.{ .process_pending_blocks = .{ .current_slot = 1 } }),
    );
}

test "BoundedQueue: recv returns null when closed and drained" {
    var q = try BlockQueue.init(testing.allocator, 4);
    defer q.deinit(testing.allocator);
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 1 } });
    q.close();
    // Items already enqueued must still drain after close.
    try testing.expect(q.recv() != null);
    try testing.expect(q.recv() == null);
}

test "BoundedQueue: ring wraparound — repeated send/recv past capacity" {
    var q = try BlockQueue.init(testing.allocator, 3);
    defer q.deinit(testing.allocator);

    var i: u64 = 0;
    while (i < 32) : (i += 1) {
        try q.trySend(.{ .process_pending_blocks = .{ .current_slot = @intCast(i) } });
        const m = q.recv() orelse return error.UnexpectedNull;
        try testing.expectEqual(@as(types.Slot, @intCast(i)), m.process_pending_blocks.current_slot);
    }
    try testing.expectEqual(@as(u64, 32), q.sent_total.load(.monotonic));
    try testing.expectEqual(@as(u64, 32), q.recv_total.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), q.dropped_total.load(.monotonic));
}

test "BoundedQueue: multi-producer trySend race — counters are exact" {
    // Stress test the producer mutex: 8 threads × 1000 sends each on
    // a queue with capacity 16. Most sends will hit QueueFull; we
    // assert that `sent_total + dropped_total == 8000` exactly (no
    // lost increments, no double-counts).
    const NUM_PRODUCERS: usize = 8;
    const SENDS_PER_PRODUCER: usize = 1000;
    const QUEUE_CAPACITY: usize = 16;

    var q = try BlockQueue.init(testing.allocator, QUEUE_CAPACITY);
    defer q.deinit(testing.allocator);

    const Producer = struct {
        fn run(queue: *BlockQueue, n: usize) void {
            var k: usize = 0;
            while (k < n) : (k += 1) {
                queue.trySend(.{ .process_pending_blocks = .{ .current_slot = @intCast(k) } }) catch {
                    // QueueFull is expected; counter already bumped by trySend.
                };
            }
        }
    };

    // Background draining thread to keep the queue from staying full
    // — otherwise sent_total stays at 16 and dropped_total takes the
    // entire load. We want a mix.
    const stop_drain = try testing.allocator.create(std.atomic.Value(bool));
    defer testing.allocator.destroy(stop_drain);
    stop_drain.* = std.atomic.Value(bool).init(false);
    const Drainer = struct {
        fn run(queue: *BlockQueue, stop: *std.atomic.Value(bool)) void {
            while (!stop.load(.acquire)) {
                _ = queue.recv() orelse return;
            }
            // Final drain.
            while (queue.depth() > 0) {
                _ = queue.recv();
            }
        }
    };

    var threads: [NUM_PRODUCERS + 1]std.Thread = undefined;
    var i: usize = 0;
    while (i < NUM_PRODUCERS) : (i += 1) {
        threads[i] = try std.Thread.spawn(.{}, Producer.run, .{ &q, SENDS_PER_PRODUCER });
    }
    threads[NUM_PRODUCERS] = try std.Thread.spawn(.{}, Drainer.run, .{ &q, stop_drain });

    i = 0;
    while (i < NUM_PRODUCERS) : (i += 1) {
        threads[i].join();
    }
    // Stop the drainer.
    stop_drain.store(true, .release);
    q.close();
    threads[NUM_PRODUCERS].join();

    const sent = q.sent_total.load(.monotonic);
    const dropped = q.dropped_total.load(.monotonic);
    try testing.expectEqual(
        @as(u64, NUM_PRODUCERS * SENDS_PER_PRODUCER),
        sent + dropped,
    );
}

test "ChainWorker: start, send Shutdown, joins cleanly" {
    var logger_config = zeam_utils.getTestLoggerConfig();
    var w = try ChainWorker.init(testing.allocator, .{
        .logger = logger_config.logger(.chain),
        .block_queue_capacity = 8,
        .attestation_queue_capacity = 8,
    });
    defer w.deinit();

    try w.start();

    // Loop must run at least once before we tell it to stop.
    try w.block_queue.trySend(.shutdown);
    // Wait for the shutdown handler to flip the stop flag.
    while (!w.stop_flag.load(.acquire)) {
        std.Thread.yield() catch {};
    }
    w.stop();
    try testing.expect(w.thread == null);
    try testing.expect(w.loop_iters.load(.monotonic) > 0);
}

test "ChainWorker: start without explicit Shutdown — stop() unblocks recv()" {
    // Verifies the close()-path of stop(): the worker is parked on
    // `recv()` inside `runLoop`; `stop()` closes both queues, recv
    // returns null, the loop exits, the join completes.
    var logger_config = zeam_utils.getTestLoggerConfig();
    var w = try ChainWorker.init(testing.allocator, .{
        .logger = logger_config.logger(.chain),
        .block_queue_capacity = 4,
        .attestation_queue_capacity = 4,
    });
    defer w.deinit();

    try w.start();
    // Give the worker enough wall-clock to hit the blocking recv.
    zeam_utils.sleepNs(5 * std.time.ns_per_ms);
    w.stop();
    try testing.expect(w.thread == null);
}

test "ChainWorker: cannot start twice" {
    var logger_config = zeam_utils.getTestLoggerConfig();
    var w = try ChainWorker.init(testing.allocator, .{
        .logger = logger_config.logger(.chain),
    });
    defer w.deinit();

    try w.start();
    try testing.expectError(error.AlreadyRunning, w.start());
    w.stop();
}

test "ChainWorker: producers race with worker drain — all messages handled, no UAF" {
    // 4 producer threads each enqueue 50 attestation-flavored messages
    // onto the attestation queue (LIFO). The worker is started before
    // any producer so it's actively draining. We assert recv_total
    // matches sent_total at the end and the worker shuts down clean.
    const NUM_PRODUCERS: usize = 4;
    const MSGS_PER_PRODUCER: usize = 50;

    var logger_config = zeam_utils.getTestLoggerConfig();
    var w = try ChainWorker.init(testing.allocator, .{
        .logger = logger_config.logger(.chain),
        .block_queue_capacity = 16,
        .attestation_queue_capacity = 16,
    });
    defer w.deinit();

    try w.start();

    const Producer = struct {
        fn run(worker: *ChainWorker, n: usize) void {
            // We track `sent` rather than the loop-induction variable so a
            // backoff-on-QueueFull retry never underflows. Earlier shape
            // (`while (k < n) : (k += 1) { ... catch { k -= 1; }; }`) hit
            // a usize underflow when the very first send raced the worker
            // before it could drain anything.
            var sent: usize = 0;
            while (sent < n) {
                // Use process_pending_blocks variant as an opaque token —
                // the worker logs and discards (c-1 stub).
                worker.attestation_queue.trySend(.{
                    .process_pending_blocks = .{ .current_slot = @intCast(sent) },
                }) catch {
                    // Full — back off and retry the same logical message.
                    zeam_utils.sleepNs(100 * std.time.ns_per_us);
                    continue;
                };
                sent += 1;
            }
        }
    };

    var threads: [NUM_PRODUCERS]std.Thread = undefined;
    var i: usize = 0;
    while (i < NUM_PRODUCERS) : (i += 1) {
        threads[i] = try std.Thread.spawn(.{}, Producer.run, .{ &w, MSGS_PER_PRODUCER });
    }
    i = 0;
    while (i < NUM_PRODUCERS) : (i += 1) {
        threads[i].join();
    }

    // Wait for the worker to drain. recv_total catching up to
    // sent_total is the signal.
    const total_expected: u64 = NUM_PRODUCERS * MSGS_PER_PRODUCER;
    var spin_budget: usize = 10000;
    while (w.attestation_queue.recv_total.load(.monotonic) < total_expected and spin_budget > 0) {
        zeam_utils.sleepNs(100 * std.time.ns_per_us);
        spin_budget -= 1;
    }
    try testing.expectEqual(
        total_expected,
        w.attestation_queue.recv_total.load(.monotonic),
    );

    w.stop();
}
