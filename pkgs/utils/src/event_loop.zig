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
    event_handle: xev.Async,
    event_completion: xev.Completion,
    pending_work: std.ArrayList(WorkItem),
    stop_handle: xev.Async,
    stop_completion: xev.Completion,

    pub const WorkItem = struct {
        callback: *const fn (*anyopaque) anyerror!void,
        data: *anyopaque,
    };

    const Self = @This();
    pub fn init(allocator: Allocator) !Self {
        const loop = try allocator.create(xev.Loop);
        errdefer allocator.destroy(loop);

        loop.* = try xev.Loop.init(.{});
        errdefer loop.deinit();

        var event_handle = try xev.Async.init();
        errdefer event_handle.deinit();

        var stop_handle = try xev.Async.init();
        errdefer stop_handle.deinit();

        return Self{
            .allocator = allocator,
            .loop = loop,
            .mutex = Mutex{},
            .event_handle = event_handle,
            .event_completion = undefined,
            .pending_work = std.ArrayList(WorkItem).init(allocator),
            .stop_handle = stop_handle,
            .stop_completion = undefined,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop_handle.deinit();
        self.event_handle.deinit();
        self.pending_work.deinit();

        self.loop.deinit();
        self.allocator.destroy(self.loop);
    }

    /// Starts both event and stop handlers for the event loop.
    pub fn startHandlers(self: *Self) void {
        // Start event notifications for work items
        self.event_handle.wait(
            self.loop,
            &self.event_completion,
            Self,
            self,
            // wait needs to be rearmed to keep listening for more notifs
            onEventSignal,
        );

        // Start stop notifications to stop loop
        self.stop_handle.wait(
            self.loop,
            &self.stop_completion,
            Self,
            self,
            onStopSignal,
        );
    }

    fn onEventSignal(
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

        return .rearm;
    }

    fn onStopSignal(
        userdata: ?*Self,
        _: *xev.Loop,
        _: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = result catch |err| {
            std.log.err("EventLoop stop signal error: {any}", .{err});
            return .disarm;
        };

        const self = userdata orelse return .disarm;

        // Stop the event loop
        self.loop.stop();

        return .disarm;
    }

    // Thread-safe: call from any thread to schedule work on the event loop
    pub fn scheduleWork(self: *Self, work: WorkItem) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.pending_work.append(work);
        try self.event_handle.notify();
    }

    pub fn run(self: *Self, optMode: ?xev.RunMode) !void {
        const mode = optMode orelse xev.RunMode.until_done;
        // clock event should keep rearming itself and never run out
        try self.loop.run(mode);
    }

    pub fn stop(self: *Self) void {
        self.stop_handle.notify() catch |err| {
            std.log.debug("EventLoop stop notification error: {any}", .{err});
            // Fallback to direct stop if notification fails
            self.loop.stop();
        };
    }
};

test "EventLoop: basic initialization and cleanup" {
    var event_loop = try EventLoop.init(std.testing.allocator);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    try std.testing.expect(event_loop.pending_work.items.len == 0);
}

test "EventLoop: single thread work scheduling" {
    var event_loop = try EventLoop.init(std.testing.allocator);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startHandlers();

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
    var event_loop = try EventLoop.init(std.testing.allocator);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startHandlers();

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

    var event_loop = try EventLoop.init(std.testing.allocator);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startHandlers();

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

    var event_loop = try EventLoop.init(std.testing.allocator);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startHandlers();

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
    var event_loop = try EventLoop.init(std.testing.allocator);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startHandlers();

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

test "EventLoop: graceful shutdown with async stop handler" {
    var event_loop = try EventLoop.init(std.testing.allocator);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startHandlers();

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

    // Now stop the event loop (this will notify the stop_handle)
    event_loop.stop();
}

test "EventLoop: processes pending work during shutdown" {
    var event_loop = try EventLoop.init(std.testing.allocator);
    defer {
        event_loop.stop();
        event_loop.deinit();
    }

    event_loop.startHandlers();

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

    // Run the loop to process all work
    try event_loop.run(.no_wait);

    // All 5 work items should have been processed
    try std.testing.expectEqual(@as(usize, 5), counter);

    // Stop the event loop
    event_loop.stop();

    // Counter should still be 5
    try std.testing.expectEqual(@as(usize, 5), counter);
}
