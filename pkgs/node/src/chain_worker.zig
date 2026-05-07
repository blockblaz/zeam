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
//!   * `BoundedQueue(Message)` — a thin wrapper around the stdlib
//!     consumer, multi-producer mutex+condvar protocol. Producers call
//!     `trySend` (wait-free fail-on-full) so the libp2p bridge thread
//!     never blocks on a full queue. Two consumer APIs: blocking
//!     `recv` (used by tests + any single-queue consumer) and
//!     non-blocking `tryRecv` (used by the chain-worker loop, which
//!     multiplexes two queues).
//!   * `ChainWorker` — owns the thread, two queues (block-FIFO,
//!     attestation-LIFO per the design doc §"Bounded queue,
//!     backpressure, and starvation"), stop flag, and a shared
//!     `wake_cond` so the worker wakes regardless of which queue a
//!     producer pushed into. Producers MUST send via
//!     `sendBlock`/`sendAttestation` so the wake signal is emitted.
//!     Shutdown is signalled out-of-band: `stop()` flips `stop_flag`,
//!     closes both queues, and signals `wake_cond`; the loop drains
//!     remaining messages (calling `Message.deinit` so producer-
//!     allocated heap is not leaked) and returns. There is
//!     deliberately no `Message.shutdown` variant — the queues
//!     transport real work, not control signals.
//!     The c-1 dispatch handler is a stub that logs unhandled
//!     variants and frees them via `Message.deinit`; slice c-2
//!     replaces the stub with per-variant chain-method calls.
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

// `std.Io.Threaded` is owned per-`ChainWorker`, not borrowed from
// `std.Io.Threaded.global_single_threaded`.
//
// Per @GrapeBaBa's review on PR #826: the global single-threaded
// instance is example-only — it has `.allocator = .failing` and
// `.async_limit = .nothing`, which is fine for example/test code but
// not the right shape for a real worker thread that may need to
// schedule futexes / signal blocked condvars. Production code must
// own its `Threaded` instance.
//
// `ChainWorker.init` allocates a `Threaded` on the heap (stable
// address — `Threaded.io()` stores `userdata = self` so moving the
// value after calling `io()` would dangle the pointer) and threads
// the resolved `std.Io` through `BoundedQueue.init` so every queue
// operation uses the worker's own io instance. `ChainWorker.deinit`
// calls `Threaded.deinit()` and frees the heap allocation.

/// Tagged union covering every chain-mutation entry point.
///
/// Each variant carries the data the chain-worker needs to run the
/// equivalent synchronous call as it exists today (slice b). Worker
/// shutdown is NOT modelled as a message variant — it is signalled
/// out-of-band via `ChainWorker.stop_flag` plus closing the queues plus
/// signalling the worker's wake condvar. See `ChainWorker.stop()` and
/// `ChainWorker.runLoop()`.
///
/// ## Ownership contract (the part c-2 producers MUST get right)
///
/// Every variant whose payload contains heap-owned data transfers
/// ownership of that data to the queue at `sendBlock`/`sendAttestation`
/// time. Producers MUST NOT call `deinit` on the payload after a
/// successful send: the queue holds the only valid handle to the
/// underlying allocations until the worker pops the message and calls
/// `Message.deinit` on it.
///
/// On `error.QueueFull` / `error.QueueClosed` the producer retains
/// ownership and is responsible for cleaning up. The wrapper helpers
/// (`ChainWorker.sendBlock`/`sendAttestation`) preserve this: they
/// only consume on success.
///
/// The worker is responsible for calling `Message.deinit` on every
/// message it pops (whether handled, skipped, or hit during the
/// stop drain), including in error paths from the dispatch handlers
/// it will land in c-2. `Message.deinit` switches on tag and calls the
/// appropriate per-variant cleanup; variants whose payloads are
/// plain-old-data are no-ops.
///
/// This locks the contract in code (rather than just prose) so a c-2
/// producer that calls `signed_block.deinit()` after `sendBlock` will
/// fail review (the type's API documents that the value has moved),
/// and a c-2 worker that forgets to deinit will leak audibly under
/// the standard test allocator's leak detector.
pub const Message = union(enum) {
    /// Full block import. Producer is libxev (replay path), libp2p
    /// gossip handler (after gossipsub validation), or req/resp.
    /// Owns: `signed_block` (transitively the block body's
    /// attestations + signatures slices).
    on_block: struct {
        signed_block: types.SignedBlock,
        prune_forkchoice: bool,
    },
    /// Single attestation gossip. Producer is libp2p gossip handler.
    /// `SignedAttestation` is plain-old-data (fixed-size validator id,
    /// embedded data + signature) so this variant is heap-free.
    on_gossip_attestation: networks.AttestationGossip,
    /// Aggregated-attestation gossip. Producer is libp2p gossip handler.
    /// Owns: `proof` slices inside the aggregated attestation.
    on_gossip_aggregated_attestation: types.SignedAggregatedAttestation,
    /// `processPendingBlocks` drain trigger. Producer is libxev clock
    /// (`onInterval`). Heap-free (slot is a value type).
    process_pending_blocks: struct {
        current_slot: types.Slot,
    },
    /// `processFinalizationFollowup` move-off path (slice c-2 will
    /// dispatch this; c-1 just defines the shape).
    ///
    /// Carries the producer's snapshot of `(previous_finalized,
    /// latest_finalized)` rather than letting the worker re-read from
    /// `forkChoice.fcStore` on dispatch. Rationale: the producer
    /// (typically `onBlockFollowup`) sees the exact finalization edge
    /// that just advanced; if the worker re-reads, another mutation
    /// could have moved the value forward and the worker would emit
    /// SSE events with the wrong `prev` checkpoint, or skip an
    /// intermediate finalization the producer was responsible for
    /// announcing. Matches the parameter shape of
    /// `BeamChain.processFinalizationAdvancement` (chain.zig:1660).
    ///
    /// Heap-free: `Checkpoint` is `(Root, Slot)`, a value type.
    process_finalization_followup: struct {
        previous_finalized: types.Checkpoint,
        latest_finalized: types.Checkpoint,
        prune_forkchoice: bool,
    },

    /// Free any heap-owned data on this message. The worker must call
    /// this on every message it pops, including in error paths from
    /// the c-2 dispatch handlers and during the stop-drain in
    /// `runLoop`. Idempotent against POD variants.
    pub fn deinit(self: *Message) void {
        switch (self.*) {
            .on_block => |*payload| {
                payload.signed_block.deinit();
            },
            .on_gossip_aggregated_attestation => |*payload| {
                payload.deinit();
            },
            .on_gossip_attestation,
            .process_pending_blocks,
            .process_finalization_followup,
            => {
                // Plain-old-data; nothing to free. Listed explicitly
                // so that a future variant added with heap fields
                // becomes a compile-time exhaustiveness error in this
                // switch and gets its cleanup wired correctly.
            },
        }
    }
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
/// Bounded MPSC queue — thin wrapper around `std.Io.Queue(T)`.
///
/// Per @GrapeBaBa's review on PR #826, c-1 uses the stdlib's built-in
/// queue rather than a hand-rolled mutex+condvar bounded ring. This
/// gives us:
///
///   * Wait-free producer via `put(io, &.{msg}, min=0)` (returns 0
///     when full, 1 on success, `error.Closed` after close).
///   * Wait-free single-consumer via `get(io, &buf, min=0)` (returns
///     0 when empty, 1 on success, `error.Closed` when closed AND
///     drained).
///   * Blocking single-consumer via `getOneUncancelable` for the
///     standalone-queue case (used in tests; production uses
///     `tryRecv` from `ChainWorker.runLoop`).
///
/// Ordering: FIFO. The c-1 design treats both block and attestation
/// queues as FIFO. Slice c-2 will swap the attestation queue for the
/// 1024cores intrusive lock-free MPSC node-based queue (
/// https://www.1024cores.net/home/lock-free-algorithms/queues/intrusive-mpsc-node-based-queue
/// ) to recover LIFO/freshness-ordered dispatch — the design doc
/// §"Bounded queue, backpressure, and starvation" mandates LIFO for
/// attestations. The block queue stays FIFO (safety-ordered).
///
/// Counters (`dropped_total`, `sent_total`, `recv_total`) are kept
/// outside the stdlib queue so the metrics layer can scrape them
/// without depending on private internals. They are updated on every
/// successful put / failed put / successful get; race-free for the
/// metric's purposes (Prometheus gauges/counters are inherently
/// approximate snapshots).
pub fn BoundedQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Caller-owned backing buffer. Lifetime is the caller's
        /// responsibility — `BoundedQueue.deinit` is a no-op for
        /// memory; the owner (typically `ChainWorker`) frees it.
        buf: []T,
        inner: std.Io.Queue(T),
        /// Cached `std.Io` from the owning `ChainWorker`'s
        /// `std.Io.Threaded` instance. Set once at `init` and reused
        /// on every hot-path call.
        io: std.Io,

        // Producer-observable counters. Updated outside the queue's
        // internal mutex; safe because each is monotonic and the
        // metrics layer reads with `.monotonic`.
        dropped_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        sent_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        recv_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

        pub const TrySendError = error{ QueueFull, QueueClosed };

        /// Initialise from a caller-provided buffer + `std.Io`. The
        /// caller owns both; `BoundedQueue.deinit` does not free
        /// either. The `io` instance MUST outlive the queue (in
        /// practice it comes from `ChainWorker.threaded.io()` and
        /// has the same lifetime as the worker).
        pub fn init(buf: []T, io: std.Io) Self {
            std.debug.assert(buf.len > 0);
            return .{
                .buf = buf,
                .inner = std.Io.Queue(T).init(buf),
                .io = io,
            };
        }

        /// No-op for memory; the buffer is caller-owned. Closes the
        /// queue if not already closed so any blocked getter wakes
        /// up.
        pub fn deinit(self: *Self) void {
            self.close();
        }

        /// Wait-free producer. Returns `error.QueueFull` if the queue
        /// is at capacity, `error.QueueClosed` if `close()` ran. On
        /// success, the message is enqueued and `std.Io.Queue` wakes
        /// any blocked consumer.
        pub fn trySend(self: *Self, msg: T) TrySendError!void {
            const n = self.inner.putUncancelable(self.io, &.{msg}, 0) catch |err| switch (err) {
                error.Closed => return error.QueueClosed,
            };
            if (n == 0) {
                _ = self.dropped_total.fetchAdd(1, .monotonic);
                return error.QueueFull;
            }
            _ = self.sent_total.fetchAdd(1, .monotonic);
        }

        /// Single-consumer blocking recv. Blocks until an item is
        /// available, or returns `null` if the queue is closed AND
        /// drained. The caller is responsible for any per-item
        /// cleanup (e.g. freeing payload buffers) since this returns
        /// `T` by value.
        ///
        /// Used by tests in c-1 and by any single-queue consumer.
        /// The chain-worker loop in c-1 (`ChainWorker.runLoop`) does
        /// NOT use this on the hot path because the worker draining
        /// two queues must wake when EITHER queue has work — see
        /// `tryRecv` + the worker's shared condvar in `ChainWorker`.
        pub fn recv(self: *Self) ?T {
            const item = self.inner.getOneUncancelable(self.io) catch |err| switch (err) {
                error.Closed => return null,
            };
            _ = self.recv_total.fetchAdd(1, .monotonic);
            return item;
        }

        /// Single-consumer non-blocking recv. Returns `null` when the
        /// queue is empty (whether closed or not). Used by the
        /// chain-worker loop, which multiplexes two queues and uses a
        /// shared condvar at the worker level for wakeup.
        pub fn tryRecv(self: *Self) ?T {
            var buf: [1]T = undefined;
            const n = self.inner.getUncancelable(self.io, &buf, 0) catch |err| switch (err) {
                error.Closed => return null,
            };
            if (n == 0) return null;
            _ = self.recv_total.fetchAdd(1, .monotonic);
            return buf[0];
        }

        /// Mark the queue closed and wake any waiting consumer. Idempotent.
        pub fn close(self: *Self) void {
            self.inner.close(self.io);
        }

        /// Snapshot of the current depth (`sent_total - recv_total`).
        /// Race-free for the metric's purposes — a brief stale read
        /// is acceptable since Prometheus gauges are sampled values.
        ///
        /// Note: under heavy contention this can briefly read 0 even
        /// when the queue is non-empty (producer has bumped
        /// `sent_total` but not yet entered the queue's internal
        /// mutex; or, symmetrically, consumer has dequeued but not
        /// yet bumped `recv_total`). For the lost-wakeup re-check in
        /// `ChainWorker.runLoop`, this is fine: the worker re-runs
        /// its drain loop on the next iteration and will pick up any
        /// item that was in flight.
        pub fn depth(self: *Self) usize {
            const sent_n = self.sent_total.load(.monotonic);
            const recv_n = self.recv_total.load(.monotonic);
            return @intCast(sent_n -| recv_n);
        }
    };
}

pub const BlockQueue = BoundedQueue(Message);
pub const AttestationQueue = BoundedQueue(Message);

/// Per-variant dispatch vtable.
///
/// The chain-worker is intentionally decoupled from `chain.zig` to
/// avoid a circular dependency (`chain.zig` already imports this
/// module for the queue types). Instead of `@import`-ing the chain,
/// the worker dispatches via this vtable, which the chain wires up
/// in `BeamChain.init` using `&self` as `ctx`.
///
/// All function pointers return `void`: producers fire-and-forget
/// onto the queue (see `sendBlock` / `sendAttestation`), so there
/// is no error channel back to them. Each handler is responsible
/// for catching and logging its own errors. Returning anything
/// other than `void` would force the worker to invent a
/// reply-channel for results that nobody on the producer side
/// is positioned to consume — gossipsub validation has already
/// happened upstream by the time these messages are enqueued.
///
/// `ctx` is type-erased to `*anyopaque` so that this header has no
/// dependency on `BeamChain`. The handler thunks in `chain.zig`
/// `@ptrCast` the ctx back to `*BeamChain` and invoke the real
/// chain method.
pub const Handlers = struct {
    ctx: *anyopaque,
    on_block: *const fn (ctx: *anyopaque, signed_block: types.SignedBlock, prune_forkchoice: bool) void,
    on_gossip_attestation: *const fn (ctx: *anyopaque, gossip: networks.AttestationGossip) void,
    on_gossip_aggregated_attestation: *const fn (ctx: *anyopaque, agg: types.SignedAggregatedAttestation) void,
    process_pending_blocks: *const fn (ctx: *anyopaque, current_slot: types.Slot) void,
    process_finalization_followup: *const fn (
        ctx: *anyopaque,
        previous_finalized: types.Checkpoint,
        latest_finalized: types.Checkpoint,
        prune_forkchoice: bool,
    ) void,
};

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
    /// Backing storage for the two queues — allocated in `init`,
    /// freed in `deinit`. Owned by ChainWorker; the queues hold
    /// non-owning references via `std.Io.Queue.init(buf)`.
    block_queue_buf: []Message,
    attestation_queue_buf: []Message,
    block_queue: BlockQueue,
    attestation_queue: AttestationQueue,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Single-shot guard so concurrent `stop()` callers don't both
    /// reach `t.join()` (which is UB on the second caller — the
    /// first sets `thread = null` after join, but the read at the
    /// top of `stop()` is racy). Whichever caller wins the
    /// compare-and-set runs the close+join sequence; the loser
    /// returns immediately. Same pattern as `recordFatal` in
    /// stress.zig (single-fire flag swap on entry).
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    /// Liveness counter: incremented on every loop iteration. Exposed
    /// via the `lean_chain_worker_loop_iters_total` metric (bumped
    /// from `runLoop` directly) so an external watchdog can compare
    /// scrape deltas to detect a stalled worker without touching
    /// queue state.
    loop_iters: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Shared wake mechanism. The worker drains both queues each
    /// iteration; when both are empty it parks here. Producers signal
    /// after every successful enqueue so the worker wakes regardless
    /// of which queue received the work. The mutex is only held long
    /// enough to wait/signal.
    ///
    /// ## Lock ordering with the queue mutexes
    ///
    /// `wake_mutex` and the per-queue mutexes ARE composed in one
    /// place: the worker's lost-wakeup re-check in `runLoop` holds
    /// `wake_mutex` while calling `block_queue.depth()` and
    /// `attestation_queue.depth()` (which take their own internal
    /// mutexes). The composition is safe under the rule
    ///
    ///   ORDER: wake_mutex → queue_mutex (never reverse)
    ///
    /// Producers respect this trivially: `sendBlock`/`sendAttestation`
    /// take queue_mutex (inside trySend) FIRST and release it BEFORE
    /// taking wake_mutex (inside `wake()`). The worker is the only
    /// thread that holds wake_mutex while reaching for a queue
    /// mutex, and only via `depth()` (read-only, immediately
    /// released).
    ///
    /// Future contributors who add new wake-mutex-protected paths
    /// must preserve this ordering or the lost-wakeup re-check
    /// becomes a deadlock surface.
    wake_mutex: std.Io.Mutex = .init,
    wake_cond: std.Io.Condition = .init,

    /// Owned `std.Io.Threaded` instance. Heap-allocated for pointer
    /// stability — `Threaded.io()` stores `userdata = self`, so
    /// moving the value after calling `io()` would dangle the
    /// pointer. Initialised in `init`, deinitialised in `deinit`.
    threaded: *std.Io.Threaded,
    /// Cached `std.Io` resolved once from `threaded.io()` at init.
    /// Same instance the queues hold; ChainWorker carries its own
    /// copy so `wake()` and `runLoop` don't have to reach into
    /// `block_queue.io`.
    io: std.Io,

    logger: zeam_utils.ModuleLogger,

    /// Optional dispatch vtable. `null` (the default) preserves the
    /// c-1 stub behavior: every popped message is logged-and-freed.
    /// Tests that only exercise the queue / wake / shutdown contracts
    /// leave this null. Production callers in `BeamChain.init` build
    /// a `Handlers` value using the chain as `ctx` and pass it via
    /// `InitOpts.handlers`.
    handlers: ?Handlers = null,

    pub const InitOpts = struct {
        block_queue_capacity: usize = DEFAULT_BLOCK_QUEUE_CAPACITY,
        attestation_queue_capacity: usize = DEFAULT_ATTESTATION_QUEUE_CAPACITY,
        logger: zeam_utils.ModuleLogger,
        /// Optional dispatch vtable; see `ChainWorker.handlers`.
        handlers: ?Handlers = null,
    };

    pub fn init(allocator: Allocator, opts: InitOpts) !Self {
        const threaded = try allocator.create(std.Io.Threaded);
        errdefer allocator.destroy(threaded);
        // We never call the async/concurrent VTable functions, so
        // `Threaded.init`'s `gpa` is only consulted in those code
        // paths. Pass the caller's allocator anyway — it's already
        // thread-safe in production (GeneralPurposeAllocator) so
        // there's no downside.
        threaded.* = std.Io.Threaded.init(allocator, .{});
        errdefer threaded.deinit();
        const io = threaded.io();

        const block_buf = try allocator.alloc(Message, opts.block_queue_capacity);
        errdefer allocator.free(block_buf);
        const att_buf = try allocator.alloc(Message, opts.attestation_queue_capacity);
        errdefer allocator.free(att_buf);

        return .{
            .allocator = allocator,
            .threaded = threaded,
            .io = io,
            .block_queue_buf = block_buf,
            .attestation_queue_buf = att_buf,
            .block_queue = BlockQueue.init(block_buf, io),
            .attestation_queue = AttestationQueue.init(att_buf, io),
            .logger = opts.logger,
            .handlers = opts.handlers,
        };
    }

    /// Stops (if running), frees all queue storage, and tears down
    /// the owned `Threaded` instance. Safe to call after `stop()`;
    /// no-op on an unstarted worker.
    pub fn deinit(self: *Self) void {
        if (self.thread != null) {
            self.stop();
        }
        self.block_queue.deinit();
        self.attestation_queue.deinit();
        self.allocator.free(self.block_queue_buf);
        self.allocator.free(self.attestation_queue_buf);
        self.threaded.deinit();
        self.allocator.destroy(self.threaded);
    }

    /// Send a block-flavored message and wake the worker. Returns
    /// `error.QueueFull` or `error.QueueClosed` from the underlying
    /// queue without blocking. Producers must use these wrappers
    /// rather than calling `block_queue.trySend` directly so the
    /// worker's shared wake-condvar is signalled — otherwise the
    /// worker can park on an empty block queue while attestations
    /// pile up (and vice versa).
    pub fn sendBlock(self: *Self, msg: Message) BlockQueue.TrySendError!void {
        self.block_queue.trySend(msg) catch |err| {
            if (err == error.QueueFull) {
                zeam_metrics.metrics.lean_chain_queue_dropped_total.incr(.{ .queue = "block" }) catch {};
            }
            return err;
        };
        zeam_metrics.metrics.lean_chain_queue_depth.set(
            .{ .queue = "block" },
            self.block_queue.depth(),
        ) catch {};
        self.wake();
    }

    /// Send an attestation-flavored message and wake the worker.
    /// Same wakeup contract as `sendBlock`. Bumps the same metrics
    /// family with `queue="attestation"`.
    pub fn sendAttestation(self: *Self, msg: Message) AttestationQueue.TrySendError!void {
        self.attestation_queue.trySend(msg) catch |err| {
            if (err == error.QueueFull) {
                zeam_metrics.metrics.lean_chain_queue_dropped_total.incr(.{ .queue = "attestation" }) catch {};
            }
            return err;
        };
        zeam_metrics.metrics.lean_chain_queue_depth.set(
            .{ .queue = "attestation" },
            self.attestation_queue.depth(),
        ) catch {};
        self.wake();
    }

    /// Wake the worker if it's parked. Safe to call from any
    /// producer; idempotent under spurious wakeups (the loop
    /// re-checks both queues each iteration).
    pub fn wake(self: *Self) void {
        const io = self.io;
        self.wake_mutex.lockUncancelable(io);
        defer self.wake_mutex.unlock(io);
        self.wake_cond.signal(io);
    }

    /// Spawn the loop thread. Returns an error if a thread already
    /// exists or if the OS rejects the spawn.
    pub fn start(self: *Self) !void {
        if (self.thread != null) return error.AlreadyRunning;
        self.thread = try std.Thread.spawn(.{}, runLoop, .{self});
    }

    /// Idempotent and concurrent-safe shutdown.
    ///
    /// Actual semantics (NOT a "Shutdown sentinel rides the block
    /// queue" framing — there is no Shutdown variant):
    ///
    ///   1. Single-shot CAS on `stopping`: only the first caller
    ///      proceeds; concurrent callers return immediately. Closes
    ///      the race where two threads both saw `thread != null`
    ///      and both reached `t.join()` (UB on the second).
    ///   2. Set `stop_flag` so the loop's drain-then-park guard
    ///      observes it.
    ///   3. Close both queues so any blocked standalone `recv`
    ///      returns null. The worker loop itself is woken via
    ///      the shared `wake_cond` in step 4; the queues' own
    ///      condvars are not what it parks on.
    ///   4. Signal `wake_cond` so the worker, if parked, observes
    ///      `stop_flag` and exits its drain loop.
    ///   5. `t.join()` blocks until the worker returns from its
    ///      current `dispatch()` call. If the worker is mid-handler
    ///      on a long-running message (a c-2 `on_block` doing full
    ///      STF can take hundreds of ms), `stop()` blocks for that
    ///      duration before returning. There is NO mid-handle
    ///      cancellation — dispatch handlers run to completion.
    ///
    /// On exit, any messages still in the queues at stop time are
    /// popped and freed via `Message.deinit` in `runLoop`'s post-
    /// stop drain (see `drainOnStop`), so producer-allocated heap
    /// is not leaked.
    pub fn stop(self: *Self) void {
        // CAS-on-set: only the winner runs the close+join sequence.
        // Losers return immediately.
        if (self.stopping.swap(true, .acq_rel)) return;
        if (self.thread == null) return;
        self.stop_flag.store(true, .release);
        self.block_queue.close();
        self.attestation_queue.close();
        self.wake();
        if (self.thread) |t| {
            t.join();
        }
        self.thread = null;
    }

    /// Worker thread main loop. Each iteration drains the block queue
    /// first (FIFO, safety-ordered) then the attestation queue (LIFO,
    /// freshness-ordered) per the design doc. When BOTH queues are
    /// empty, the worker parks on the shared `wake_cond`, which any
    /// producer signals via `sendBlock` / `sendAttestation`, and `stop`
    /// signals after closing the queues.
    ///
    /// Exit condition: `stop_flag == true` AND both queues are
    /// drained. On exit, any messages still in the queues are popped
    /// and freed via `Message.deinit` so producer-allocated heap is
    /// not leaked when shutdown races a partial enqueue burst.
    fn runLoop(self: *Self) void {
        self.logger.info("chain-worker: loop started", .{});
        const io = self.io;
        while (true) {
            _ = self.loop_iters.fetchAdd(1, .monotonic);
            zeam_metrics.metrics.lean_chain_worker_loop_iters_total.incr();

            // Drain block queue first (highest priority). `tryRecv`
            // never blocks; we keep draining until empty.
            if (self.block_queue.tryRecv()) |msg| {
                self.dispatch(msg);
                continue;
            }

            // Then attestation queue.
            if (self.attestation_queue.tryRecv()) |msg| {
                self.dispatch(msg);
                continue;
            }

            // Both queues empty this round. Check stop condition
            // BEFORE parking: if stop was requested while we were
            // draining, drain anything that arrived after the last
            // probe and exit.
            if (self.stop_flag.load(.acquire)) {
                self.drainOnStop();
                break;
            }

            // Park on the shared wake-cond. Any producer that calls
            // sendBlock / sendAttestation will signal it, as will
            // `stop()`. We re-check both queues + the stop flag on
            // wake so a spurious wakeup is harmless.
            self.wake_mutex.lockUncancelable(io);
            // Re-check under the wake mutex to avoid the lost-wakeup
            // race: a producer that ran trySend + wake between our
            // last drain and our park here would have signalled an
            // unparked worker; without this re-check we'd sleep
            // forever even though there is work pending.
            if (self.block_queue.depth() == 0 and
                self.attestation_queue.depth() == 0 and
                !self.stop_flag.load(.acquire))
            {
                self.wake_cond.waitUncancelable(io, &self.wake_mutex);
            }
            self.wake_mutex.unlock(io);
        }
        self.logger.info("chain-worker: loop stopped", .{});
    }

    /// Pop and free every remaining message in both queues without
    /// running their handler logic. Called from `runLoop` once the
    /// stop flag is observed; ensures producer-allocated heap is not
    /// leaked when stop races a partial enqueue burst.
    fn drainOnStop(self: *Self) void {
        var freed: usize = 0;
        while (self.block_queue.tryRecv()) |popped| {
            var m = popped;
            m.deinit();
            freed += 1;
        }
        while (self.attestation_queue.tryRecv()) |popped| {
            var m = popped;
            m.deinit();
            freed += 1;
        }
        if (freed > 0) {
            self.logger.info(
                "chain-worker: stop drain freed {d} unprocessed message(s)",
                .{freed},
            );
        }
    }

    /// Per-variant dispatch into the chain (c-2b commit 3). When
    /// `handlers` is null we fall back to the c-1 stub semantics —
    /// log the variant and free it. This keeps the unit tests in
    /// this module (which only stress the queue / wake / shutdown
    /// contracts) working unchanged: they leave `handlers = null`,
    /// so popping any message simply logs and frees.
    ///
    /// When `handlers` is set, we route by tag into the supplied
    /// function pointers. Handlers are responsible for their own
    /// error logging (the producer side fired-and-forgot the
    /// message at queue-push time and is no longer in a position
    /// to react). After the handler returns, `defer m.deinit()`
    /// frees any heap-owned payload — the worker remains the sole
    /// owner from `tryRecv` through handler return, regardless of
    /// whether the handler succeeded or threw internally.
    fn dispatch(self: *Self, msg: Message) void {
        var m = msg;
        defer m.deinit();
        const h = self.handlers orelse {
            // No vtable wired (c-1 stub / queue-only tests). Log and
            // drop: the message will be deinit'd by the defer above.
            self.logger.warn(
                "chain-worker: dropping message (no handlers wired): {s}",
                .{@tagName(m)},
            );
            return;
        };
        switch (m) {
            .on_block => |payload| h.on_block(h.ctx, payload.signed_block, payload.prune_forkchoice),
            .on_gossip_attestation => |gossip| h.on_gossip_attestation(h.ctx, gossip),
            .on_gossip_aggregated_attestation => |agg| h.on_gossip_aggregated_attestation(h.ctx, agg),
            .process_pending_blocks => |payload| h.process_pending_blocks(h.ctx, payload.current_slot),
            .process_finalization_followup => |payload| h.process_finalization_followup(
                h.ctx,
                payload.previous_finalized,
                payload.latest_finalized,
                payload.prune_forkchoice,
            ),
        }
    }
};

// =====================================================================
// Tests
// =====================================================================

const testing = std.testing;

/// Helper for standalone-queue tests: build a `std.Io.Threaded` on the
/// stack, return its `io()`. The Threaded MUST outlive every queue
/// operation that uses the returned io — callers keep a `var threaded`
/// adjacent to the queue and `defer threaded.deinit()`.
///
/// The `init_single_threaded` static would also work for the
/// non-async/non-concurrent paths these tests exercise, but mirroring
/// production usage (each owner builds its own Threaded) keeps the
/// test surface honest about the dependency.
fn testThreadedInit() std.Io.Threaded {
    return std.Io.Threaded.init(testing.allocator, .{});
}

test "BoundedQueue: trySend / recv preserves FIFO order" {
    var threaded = testThreadedInit();
    defer threaded.deinit();
    const buf = try testing.allocator.alloc(Message, 4);
    defer testing.allocator.free(buf);
    var q = BlockQueue.init(buf, threaded.io());
    defer q.deinit();

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

// Note: c-1 dropped LIFO mode — both queues are FIFO until c-2
// swaps the attestation queue for a 1024cores intrusive MPSC node
// queue (per @GrapeBaBa's review). The previous LIFO test is
// removed; the FIFO test above covers the only ordering surface
// that exists in c-1.

test "BoundedQueue: another FIFO ordering check (head walk)" {
    // Sanity that ordering is preserved across send/recv
    // interleaving — distinct from the wraparound test below which
    // hits the ring boundaries explicitly.
    var threaded = testThreadedInit();
    defer threaded.deinit();
    const buf = try testing.allocator.alloc(Message, 4);
    defer testing.allocator.free(buf);
    var q = AttestationQueue.init(buf, threaded.io());
    defer q.deinit();

    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 1 } });
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 2 } });
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 3 } });

    const m1 = q.recv() orelse return error.UnexpectedNull;
    try testing.expectEqual(@as(types.Slot, 1), m1.process_pending_blocks.current_slot);
    const m2 = q.recv() orelse return error.UnexpectedNull;
    try testing.expectEqual(@as(types.Slot, 2), m2.process_pending_blocks.current_slot);
    const m3 = q.recv() orelse return error.UnexpectedNull;
    try testing.expectEqual(@as(types.Slot, 3), m3.process_pending_blocks.current_slot);

    q.close();
    try testing.expect(q.recv() == null);
}

test "BoundedQueue: trySend returns QueueFull at capacity, increments dropped_total" {
    var threaded = testThreadedInit();
    defer threaded.deinit();
    const buf = try testing.allocator.alloc(Message, 2);
    defer testing.allocator.free(buf);
    var q = BlockQueue.init(buf, threaded.io());
    defer q.deinit();

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
    var threaded = testThreadedInit();
    defer threaded.deinit();
    const buf = try testing.allocator.alloc(Message, 4);
    defer testing.allocator.free(buf);
    var q = BlockQueue.init(buf, threaded.io());
    defer q.deinit();
    q.close();
    try testing.expectError(
        error.QueueClosed,
        q.trySend(.{ .process_pending_blocks = .{ .current_slot = 1 } }),
    );
}

test "BoundedQueue: recv returns null when closed and drained" {
    var threaded = testThreadedInit();
    defer threaded.deinit();
    const buf = try testing.allocator.alloc(Message, 4);
    defer testing.allocator.free(buf);
    var q = BlockQueue.init(buf, threaded.io());
    defer q.deinit();
    try q.trySend(.{ .process_pending_blocks = .{ .current_slot = 1 } });
    q.close();
    // Items already enqueued must still drain after close.
    try testing.expect(q.recv() != null);
    try testing.expect(q.recv() == null);
}

test "BoundedQueue: ring wraparound — head walks past capacity-1 with items live" {
    // The wrapped `std.Io.Queue` does its own ring-buffer index
    // management; this test asserts FIFO sequence holds across many
    // wrap cycles. Earlier (hand-rolled queue) shape was send-1 /
    // recv-1 × 32 with depth=1 throughout, which only proved the
    // modular index math doesn't trip on head=0. Present pattern
    // alternates fill-to-capacity / drain-all-but-one so head walks
    // past every position in [0, capacity) while at least one item
    // is always live; FIFO sequence asserted on every pop.
    const cap: usize = 4;
    var threaded = testThreadedInit();
    defer threaded.deinit();
    const buf = try testing.allocator.alloc(Message, cap);
    defer testing.allocator.free(buf);
    var q = BlockQueue.init(buf, threaded.io());
    defer q.deinit();

    var next_send: u64 = 0;
    var next_recv: u64 = 0;

    // Outer loop: enough iterations that head wraps the ring at
    // least 4 times.
    var round: usize = 0;
    while (round < 16) : (round += 1) {
        // Fill to capacity.
        while (q.depth() < cap) {
            try q.trySend(.{ .process_pending_blocks = .{ .current_slot = @intCast(next_send) } });
            next_send += 1;
        }
        try testing.expectEqual(cap, q.depth());

        // Drain all-but-one. The remaining item sits at
        // (head + len - 1) % cap which, as head walks the ring,
        // exercises every slot of `items[]`.
        var keep: usize = 0;
        while (q.depth() > 1) {
            const m = q.recv() orelse return error.UnexpectedNull;
            try testing.expectEqual(
                @as(types.Slot, @intCast(next_recv)),
                m.process_pending_blocks.current_slot,
            );
            next_recv += 1;
            keep += 1;
        }
        try testing.expectEqual(@as(usize, 1), q.depth());
        try testing.expect(keep == cap - 1);
    }

    // Final drain. Every value popped must still match the FIFO
    // sequence — if any wraparound mishandling silently re-ordered
    // the ring, this assertion fires.
    while (q.depth() > 0) {
        const m = q.recv() orelse return error.UnexpectedNull;
        try testing.expectEqual(
            @as(types.Slot, @intCast(next_recv)),
            m.process_pending_blocks.current_slot,
        );
        next_recv += 1;
    }

    try testing.expectEqual(next_send, next_recv);
    try testing.expectEqual(next_send, q.sent_total.load(.monotonic));
    try testing.expectEqual(next_send, q.recv_total.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), q.dropped_total.load(.monotonic));

    // Sanity: head must have wrapped at least once (next_send / cap
    // ≥ round count) so the test name is honest.
    try testing.expect(next_send / cap >= 4);
}

test "BoundedQueue: multi-producer trySend race — counters are exact" {
    // Stress test the producer mutex: 8 threads × 1000 sends each on
    // a queue with capacity 16. Most sends will hit QueueFull; we
    // assert that `sent_total + dropped_total == 8000` exactly (no
    // lost increments, no double-counts).
    const NUM_PRODUCERS: usize = 8;
    const SENDS_PER_PRODUCER: usize = 1000;
    const QUEUE_CAPACITY: usize = 16;

    var threaded = testThreadedInit();
    defer threaded.deinit();
    const buf = try testing.allocator.alloc(Message, QUEUE_CAPACITY);
    defer testing.allocator.free(buf);
    var q = BlockQueue.init(buf, threaded.io());
    defer q.deinit();

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

test "ChainWorker: start, send a message, stop() drains and joins cleanly" {
    var logger_config = zeam_utils.getTestLoggerConfig();
    var w = try ChainWorker.init(testing.allocator, .{
        .logger = logger_config.logger(.chain),
        .block_queue_capacity = 8,
        .attestation_queue_capacity = 8,
    });
    defer w.deinit();

    try w.start();

    // Send a POD message (no heap to manage) and wait until the
    // worker has dispatched it. process_pending_blocks is heap-free
    // so the dispatcher's `Message.deinit` is a no-op — the test
    // observes wake-then-handle without the test allocator's leak
    // detector seeing anything.
    try w.sendBlock(.{ .process_pending_blocks = .{ .current_slot = 7 } });
    while (w.block_queue.recv_total.load(.monotonic) < 1) {
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

test "ChainWorker: queue accounting under producer race — sent_total and recv_total agree" {
    // 4 producer threads each enqueue 50 attestation-flavored
    // messages. The worker is started before any producer so it's
    // actively draining. We assert recv_total matches sent_total
    // at the end and the worker shuts down clean.
    //
    // What this test does prove:
    //   * Producer-side mutex never loses a sent_total increment
    //     under contention.
    //   * Worker-side single-consumer never loses a recv_total
    //     increment under contention.
    //   * The wake_cond chain (sendAttestation → wake → worker park
    //     re-check) eventually drains every produced message.
    //   * stop()+drainOnStop completes without deadlock.
    //
    // What this test does NOT prove (despite an earlier name that
    // implied it):
    //   * That the dispatch handler ran any business logic. The
    //     c-1 stub for `process_pending_blocks` logs and returns;
    //     `recv_total` is bumped inside `tryRecv` regardless of
    //     what `dispatch` does. A c-2 handler that did real work
    //     could still pass this test even if its STF was a no-op.
    //   * That there's no UAF on the message payload. The variant
    //     used here (`process_pending_blocks`) is heap-free, so
    //     there is no UAF surface to exercise. The Message.deinit
    //     leak tests above cover the heap-bearing variants; a
    //     genuine UAF assertion would land alongside c-2's real
    //     handlers.
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
                worker.sendAttestation(.{
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

test "Message.deinit: on_block frees the SignedBlock heap (no leak under testing.allocator)" {
    // Build a SignedBlock that owns heap (attestations + signatures
    // lists), wrap it in a Message, and verify deinit cleans up.
    // testing.allocator panics on leak so the assertion is implicit.
    const attestations = try types.AggregatedAttestations.init(testing.allocator);
    const signatures = try types.createBlockSignatures(testing.allocator, attestations.len());

    var msg: Message = .{
        .on_block = .{
            .signed_block = .{
                .block = .{
                    .slot = 9,
                    .proposer_index = 3,
                    .parent_root = std.mem.zeroes(types.Root),
                    .state_root = std.mem.zeroes(types.Root),
                    .body = .{ .attestations = attestations },
                },
                .signature = signatures,
            },
            .prune_forkchoice = false,
        },
    };
    msg.deinit();
}

test "Message.deinit: POD variants are no-ops" {
    // process_pending_blocks, on_gossip_attestation, and
    // process_finalization_followup carry no heap. deinit must
    // succeed without freeing anything (and without compiler errors
    // from the exhaustiveness switch).
    var pending: Message = .{ .process_pending_blocks = .{ .current_slot = 42 } };
    pending.deinit();

    var attn: Message = .{
        .on_gossip_attestation = .{
            .subnet_id = 0,
            .message = .{
                .validator_id = 0,
                .message = std.mem.zeroes(types.AttestationData),
                .signature = std.mem.zeroes(types.SIGBYTES),
            },
        },
    };
    attn.deinit();

    var fin: Message = .{
        .process_finalization_followup = .{
            .previous_finalized = .{ .root = std.mem.zeroes(types.Root), .slot = 0 },
            .latest_finalized = .{ .root = std.mem.zeroes(types.Root), .slot = 8 },
            .prune_forkchoice = true,
        },
    };
    fin.deinit();
}

test "ChainWorker.drainOnStop: pending messages freed on shutdown (no leak)" {
    // Enqueue a heap-owning Message, then immediately stop the worker
    // BEFORE it has a chance to dispatch. The drainOnStop path must
    // pop the message and call Message.deinit, otherwise testing.
    // allocator's leak detector trips when the queue's storage is
    // freed and the inner allocations are still live.
    var logger_config = zeam_utils.getTestLoggerConfig();
    var w = try ChainWorker.init(testing.allocator, .{
        .logger = logger_config.logger(.chain),
        .block_queue_capacity = 4,
        .attestation_queue_capacity = 4,
    });
    defer w.deinit();

    // Build the heap-owning payload before starting the worker so the
    // race against dispatch is deterministic: we never start it.
    // Without start(), runLoop never runs; instead we exercise
    // drainOnStop via stop() directly. stop() is safe to call with no
    // running thread (it returns early), so we instead call the
    // private drain by way of: start, immediate stop, deinit. The
    // worker may or may not have popped the message before stop;
    // either way, no heap should leak.
    const attestations = try types.AggregatedAttestations.init(testing.allocator);
    const signatures = try types.createBlockSignatures(testing.allocator, attestations.len());
    const msg: Message = .{
        .on_block = .{
            .signed_block = .{
                .block = .{
                    .slot = 1,
                    .proposer_index = 0,
                    .parent_root = std.mem.zeroes(types.Root),
                    .state_root = std.mem.zeroes(types.Root),
                    .body = .{ .attestations = attestations },
                },
                .signature = signatures,
            },
            .prune_forkchoice = false,
        },
    };

    try w.start();
    try w.sendBlock(msg);
    // Don't wait for the worker to dispatch — race the stop. Either
    // dispatch() runs deinit first, or drainOnStop runs it. Both
    // paths must free.
    w.stop();
}

test "ChainWorker: metrics — sendBlock/sendAttestation/runLoop bump lean_chain_* and appear in /metrics output" {
    // Slice-(b) lesson (locking.zig LockTimer test): manual metric-
    // wiring audits regress silently. This test exercises the three
    // chain-worker metrics end-to-end:
    //
    //   * lean_chain_queue_dropped_total{queue=...}  (from a forced
    //     QueueFull on a capacity-1 queue),
    //   * lean_chain_queue_depth{queue=...}  (set on every successful
    //     send),
    //   * lean_chain_worker_loop_iters_total  (incremented on every
    //     runLoop iteration).
    //
    // It then scrapes the rendered Prometheus body via
    // zeam_metrics.writeMetrics and asserts each name + label appears,
    // mirroring the LockTimer test pattern. Uses page_allocator for
    // the metrics init so the (process-global) hashmap survives test
    // teardown — see locking.zig comment on the same trap.
    try zeam_metrics.init(std.heap.page_allocator);

    var logger_config = zeam_utils.getTestLoggerConfig();
    var w = try ChainWorker.init(testing.allocator, .{
        .logger = logger_config.logger(.chain),
        // capacity 1 so the second sendBlock below is guaranteed to
        // hit QueueFull and bump lean_chain_queue_dropped_total.
        .block_queue_capacity = 1,
        .attestation_queue_capacity = 1,
    });
    defer w.deinit();

    // 1) Send one block successfully → bumps lean_chain_queue_depth.
    try w.sendBlock(.{ .process_pending_blocks = .{ .current_slot = 1 } });

    // 2) Force a drop on the block queue. The worker isn't started, so
    //    the queue stays at capacity. The 2nd sendBlock returns
    //    QueueFull and bumps lean_chain_queue_dropped_total{queue=block}.
    try testing.expectError(
        error.QueueFull,
        w.sendBlock(.{ .process_pending_blocks = .{ .current_slot = 2 } }),
    );

    // 3) Same shape on the attestation queue.
    try w.sendAttestation(.{ .process_pending_blocks = .{ .current_slot = 3 } });
    try testing.expectError(
        error.QueueFull,
        w.sendAttestation(.{ .process_pending_blocks = .{ .current_slot = 4 } }),
    );

    // 4) Start the worker briefly so runLoop runs at least once and
    //    bumps lean_chain_worker_loop_iters_total.
    try w.start();
    while (w.loop_iters.load(.monotonic) < 1) {
        std.Thread.yield() catch {};
    }
    w.stop();

    // 5) Scrape /metrics via writeMetrics and assert each metric +
    //    label is in the rendered body.
    var alloc_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc_writer.deinit();
    try zeam_metrics.writeMetrics(&alloc_writer.writer);
    const body = alloc_writer.writer.buffered();

    try testing.expect(std.mem.indexOf(u8, body, "lean_chain_queue_dropped_total") != null);
    try testing.expect(std.mem.indexOf(u8, body, "lean_chain_queue_depth") != null);
    try testing.expect(std.mem.indexOf(u8, body, "lean_chain_worker_loop_iters_total") != null);

    try testing.expect(std.mem.indexOf(u8, body, "queue=\"block\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "queue=\"attestation\"") != null);
}

test "ChainWorker.stop: idempotent under concurrent callers (no double-join UB)" {
    // Three threads race stop() against each other on a started worker.
    // Without the `stopping` CAS guard, all three would observe
    // `thread != null`, all three would proceed past the early return,
    // and at least two would call `t.join()` on the same handle —
    // UB on the second join.
    //
    // With the guard, exactly one caller wins the CAS and runs the
    // close+join sequence; the other two return immediately. The test
    // asserts the worker shut down (loop_iters > 0, thread null) and
    // that no thread crashed.
    var logger_config = zeam_utils.getTestLoggerConfig();
    var w = try ChainWorker.init(testing.allocator, .{
        .logger = logger_config.logger(.chain),
        .block_queue_capacity = 4,
        .attestation_queue_capacity = 4,
    });
    defer w.deinit();

    try w.start();
    // Let the worker reach its parked state.
    zeam_utils.sleepNs(2 * std.time.ns_per_ms);

    const Stopper = struct {
        fn run(worker: *ChainWorker) void {
            worker.stop();
        }
    };

    var threads: [3]std.Thread = undefined;
    var i: usize = 0;
    while (i < threads.len) : (i += 1) {
        threads[i] = try std.Thread.spawn(.{}, Stopper.run, .{&w});
    }
    i = 0;
    while (i < threads.len) : (i += 1) {
        threads[i].join();
    }

    try testing.expect(w.thread == null);
    try testing.expect(w.loop_iters.load(.monotonic) > 0);
    // Calling stop again from the test thread must also be safe.
    w.stop();
}
