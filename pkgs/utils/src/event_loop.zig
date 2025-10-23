const std = @import("std");
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const Allocator = std.mem.Allocator;

const xev = @import("xev");

pub const EventLoopError = error{
    ShuttingDown,
};

pub const EventLoop = struct {
    allocator: Allocator,
    loop: *xev.Loop,
    // events from libp2p or other threads will also be pushed on it
    mutex: Mutex,
    async_notifier: xev.Async,
    async_completion: xev.Completion,
    pending_work: std.ArrayList(WorkItem),
    stopping: std.atomic.Value(bool),

    pub const WorkItem = struct {
        callback: *const fn (*anyopaque) anyerror!void,
        data: *anyopaque,
    };

    const Self = @This();
    pub fn init(allocator: Allocator, loop: *xev.Loop) !Self {
        var async_notifier = try xev.Async.init();
        errdefer async_notifier.deinit();

        return Self{
            .allocator = allocator,
            .loop = loop,
            .mutex = Mutex{},
            .async_notifier = async_notifier,
            .async_completion = undefined,
            .pending_work = std.ArrayList(WorkItem).init(allocator),
            .stopping = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *Self) void {
        self.async_notifier.deinit();
        self.pending_work.deinit();
    }

    /// Initiates graceful shutdown of the event loop.
    /// This method signals the event loop to stop, sends a notification for pending work,
    /// and attempts to process it immediately with a best-effort loop run.
    /// Should be called before deinit().
    pub fn stop(self: *Self) void {
        // Signal that we're stopping - the next time the loop runs, it will disarm
        self.stopping.store(true, .monotonic);

        // Try to trigger a notification if there's pending work
        self.mutex.lock();
        const has_work = self.pending_work.items.len > 0;
        self.mutex.unlock();

        if (has_work) {
            self.async_notifier.notify() catch |err| {
                std.log.debug("EventLoop stop: notify failed: {any}", .{err});
                return;
            };

            // Best-effort attempt to process pending work immediately
            // Only run the loop if we successfully notified about pending work
            // This may fail if the loop has active events (timers, etc.)
            self.loop.run(.no_wait) catch |err| {
                std.log.debug("EventLoop stop: immediate processing skipped (may be normal with active timers): {any}", .{err});
            };
        }
    }

    pub fn startAsyncNotifications(self: *Self) void {
        self.async_notifier.wait(
            self.loop,
            &self.async_completion,
            Self,
            self,
            // wait needs to be rearmed to keep listening for more notifs
            onAsyncNotify,
        );
    }

    fn onAsyncNotify(
        userdata: ?*Self,
        _: *xev.Loop,
        _: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = result catch |err| {
            std.log.err("EventLoop async notification error: {any}", .{err});
            return .rearm;
        };

        const self = userdata orelse return .rearm;

        self.mutex.lock();
        defer self.mutex.unlock();

        // Take all pending work items
        const work_items = self.pending_work.toOwnedSlice() catch |err| {
            std.log.err("EventLoop failed to get work items: {any}", .{err});
            return .rearm;
        };
        defer self.allocator.free(work_items);

        // Process all work items on the main thread
        for (work_items) |item| {
            item.callback(item.data) catch |err| {
                std.log.warn("EventLoop work item callback error: {any}", .{err});
            };
        }

        // Check if we should stop accepting new notifications
        if (self.stopping.load(.monotonic)) {
            std.log.debug("EventLoop stopping - disarming async notifications", .{});
            return .disarm;
        }

        return .rearm;
    }

    // Thread-safe: call from any thread to schedule work on the event loop
    pub fn scheduleWork(self: *Self, work: WorkItem) !void {
        // Check if we're shutting down before acquiring the lock
        if (self.stopping.load(.monotonic)) {
            return EventLoopError.ShuttingDown;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        // Double-check after acquiring lock (stop() might have been called concurrently)
        if (self.stopping.load(.monotonic)) {
            return EventLoopError.ShuttingDown;
        }

        try self.pending_work.append(work);
        try self.async_notifier.notify();
    }

    pub fn run(self: *Self, optMode: ?xev.RunMode) !void {
        const mode = optMode orelse xev.RunMode.until_done;
        // clock event should keep rearming itself and never run out
        try self.loop.run(mode);
    }
};

test "EventLoop: basic initialization and cleanup" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var event_loop = try EventLoop.init(std.testing.allocator, &loop);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    try std.testing.expect(event_loop.pending_work.items.len == 0);
}

test "EventLoop: single thread work scheduling" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var event_loop = try EventLoop.init(std.testing.allocator, &loop);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startAsyncNotifications();

    // Test data
    var counter: usize = 0;
    const test_callback = struct {
        fn callback(data: *anyopaque) anyerror!void {
            const count: *usize = @ptrCast(@alignCast(data));
            count.* += 1;
        }
    }.callback;

    // Schedule work
    const work = EventLoop.WorkItem{
        .callback = test_callback,
        .data = &counter,
    };
    try event_loop.scheduleWork(work);

    // Run the loop to process the work
    try event_loop.run(.no_wait);

    // Verify work was executed
    try std.testing.expectEqual(@as(usize, 1), counter);
}

test "EventLoop: multiple work items in sequence" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var event_loop = try EventLoop.init(std.testing.allocator, &loop);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startAsyncNotifications();

    var counter: usize = 0;
    const test_callback = struct {
        fn callback(data: *anyopaque) anyerror!void {
            const count: *usize = @ptrCast(@alignCast(data));
            count.* += 1;
        }
    }.callback;

    // Schedule multiple work items
    for (0..5) |_| {
        const work = EventLoop.WorkItem{
            .callback = test_callback,
            .data = &counter,
        };
        try event_loop.scheduleWork(work);
    }

    // Run the loop to process all work
    try event_loop.run(.no_wait);

    // All 5 work items should have been executed
    try std.testing.expectEqual(@as(usize, 5), counter);
}

test "EventLoop: cross-thread work scheduling" {
    const TestContext = struct {
        counter: *usize,
        work_thread_id: *std.Thread.Id,
    };

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var event_loop = try EventLoop.init(std.testing.allocator, &loop);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startAsyncNotifications();

    // Shared state between threads
    var counter: usize = 0;
    var thread_id_main: std.Thread.Id = undefined;
    var thread_id_worker: std.Thread.Id = undefined;
    var work_thread_id: std.Thread.Id = undefined;

    thread_id_main = std.Thread.getCurrentId();

    const test_callback = struct {
        fn callback(data: *anyopaque) anyerror!void {
            const ctx: *TestContext = @ptrCast(@alignCast(data));
            ctx.counter.* += 1;
            ctx.work_thread_id.* = std.Thread.getCurrentId();
        }
    }.callback;

    var ctx = TestContext{
        .counter = &counter,
        .work_thread_id = &work_thread_id,
    };

    // Spawn a worker thread that schedules work
    const WorkerThread = struct {
        fn run(el: *EventLoop, context: *TestContext, tid: *std.Thread.Id) void {
            tid.* = std.Thread.getCurrentId();

            // Schedule work from worker thread
            const work = EventLoop.WorkItem{
                .callback = test_callback,
                .data = context,
            };
            el.scheduleWork(work) catch unreachable;
        }
    };

    const worker = try std.Thread.spawn(.{}, WorkerThread.run, .{ &event_loop, &ctx, &thread_id_worker });
    worker.join();

    // Run the loop to process work from worker thread
    try event_loop.run(.no_wait);

    // Verify work was executed
    try std.testing.expectEqual(@as(usize, 1), counter);

    // Verify worker thread was different from main thread
    try std.testing.expect(thread_id_worker != thread_id_main);

    // Verify work callback executed on main thread (the one running the loop)
    try std.testing.expectEqual(thread_id_main, work_thread_id);
}

test "EventLoop: multiple threads scheduling work concurrently" {
    const TestContext = struct {
        counter: *usize,
        mutex: *std.Thread.Mutex,
    };

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var event_loop = try EventLoop.init(std.testing.allocator, &loop);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startAsyncNotifications();

    var counter: usize = 0;
    var mutex = std.Thread.Mutex{};

    const test_callback = struct {
        fn callback(data: *anyopaque) anyerror!void {
            const ctx: *TestContext = @ptrCast(@alignCast(data));
            ctx.mutex.lock();
            defer ctx.mutex.unlock();
            ctx.counter.* += 1;
        }
    }.callback;

    var ctx = TestContext{
        .counter = &counter,
        .mutex = &mutex,
    };

    const WorkerThread = struct {
        fn run(el: *EventLoop, context: *TestContext, iterations: usize) void {
            for (0..iterations) |_| {
                const work = EventLoop.WorkItem{
                    .callback = test_callback,
                    .data = context,
                };
                el.scheduleWork(work) catch unreachable;
            }
        }
    };

    const num_threads = 4;
    const iterations_per_thread = 10;
    var threads: [num_threads]std.Thread = undefined;

    // Spawn multiple worker threads
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, WorkerThread.run, .{ &event_loop, &ctx, iterations_per_thread });
    }

    // Wait for all threads to finish scheduling
    for (threads) |thread| {
        thread.join();
    }

    // Run the loop to process all work
    // May need multiple runs as notifications can be coalesced
    var max_iterations: usize = 100;
    while (max_iterations > 0) : (max_iterations -= 1) {
        try event_loop.run(.no_wait);

        mutex.lock();
        const current_count = counter;
        mutex.unlock();

        if (current_count == num_threads * iterations_per_thread) {
            break;
        }

        std.time.sleep(1 * std.time.ns_per_ms);
    }

    // Verify all work items were executed
    try std.testing.expectEqual(@as(usize, num_threads * iterations_per_thread), counter);
}

test "EventLoop: error handling in work callback" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var event_loop = try EventLoop.init(std.testing.allocator, &loop);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startAsyncNotifications();

    var counter: usize = 0;

    const error_callback = struct {
        fn callback(data: *anyopaque) anyerror!void {
            const count: *usize = @ptrCast(@alignCast(data));
            count.* += 1;
            return error.TestError;
        }
    }.callback;

    const success_callback = struct {
        fn callback(data: *anyopaque) anyerror!void {
            const count: *usize = @ptrCast(@alignCast(data));
            count.* += 10;
        }
    }.callback;

    // Schedule work that will error
    try event_loop.scheduleWork(.{
        .callback = error_callback,
        .data = &counter,
    });

    // Schedule work that will succeed (should still run after error)
    try event_loop.scheduleWork(.{
        .callback = success_callback,
        .data = &counter,
    });

    // Run the loop
    try event_loop.run(.no_wait);

    // Both callbacks should have executed (error is logged but doesn't stop processing)
    try std.testing.expectEqual(@as(usize, 11), counter);
}

test "EventLoop: graceful shutdown and rejection of new work" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var event_loop = try EventLoop.init(std.testing.allocator, &loop);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startAsyncNotifications();

    var counter: usize = 0;

    const test_callback = struct {
        fn callback(data: *anyopaque) anyerror!void {
            const count: *usize = @ptrCast(@alignCast(data));
            count.* += 1;
        }
    }.callback;

    // Schedule work before stopping
    try event_loop.scheduleWork(.{
        .callback = test_callback,
        .data = &counter,
    });

    // Run the loop to process the work
    try event_loop.run(.no_wait);

    // Verify the work was executed
    try std.testing.expectEqual(@as(usize, 1), counter);

    // Now stop the event loop (this will process pending work and disarm)
    event_loop.stop();

    // Try to schedule new work after stopping
    const result = event_loop.scheduleWork(.{
        .callback = test_callback,
        .data = &counter,
    });

    // Should return ShuttingDown error
    try std.testing.expectError(EventLoopError.ShuttingDown, result);

    // Run the loop again - counter should NOT increase since loop is disarmed
    try event_loop.run(.no_wait);

    // Counter should still be 1 (no new work was processed)
    try std.testing.expectEqual(@as(usize, 1), counter);
}

test "EventLoop: processes pending work during shutdown" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var event_loop = try EventLoop.init(std.testing.allocator, &loop);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startAsyncNotifications();

    var counter: usize = 0;

    const test_callback = struct {
        fn callback(data: *anyopaque) anyerror!void {
            const count: *usize = @ptrCast(@alignCast(data));
            count.* += 1;
        }
    }.callback;

    // Schedule multiple work items
    for (0..5) |_| {
        try event_loop.scheduleWork(.{
            .callback = test_callback,
            .data = &counter,
        });
    }

    // Stop the event loop (this will process all pending work)
    event_loop.stop();

    // All 5 work items should have been processed during stop()
    try std.testing.expectEqual(@as(usize, 5), counter);

    // Try to schedule more work - should fail
    const result = event_loop.scheduleWork(.{
        .callback = test_callback,
        .data = &counter,
    });
    try std.testing.expectError(EventLoopError.ShuttingDown, result);

    // Counter should still be 5
    try std.testing.expectEqual(@as(usize, 5), counter);
}
