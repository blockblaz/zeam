//! Process-wide blocking Io for zeam's internal blocking primitives (SyncMutex,
//! logger, sleep, and other leaf code that cannot practically take an Io
//! parameter). Installed once at startup from main's process Io
//! (std.process.Init.io). This deliberately replaces std's debug-only
//! std.Io.Threaded.global_single_threaded for production code.
const std = @import("std");

/// The real process Io, installed once by main before any worker threads spawn.
var installed: ?std.Io = null;
/// Deliberate local fallback for tests / pre-install bootstrap. Not std's
/// debug-only global instance — a zeam-owned single-threaded Threaded.
var fallback_instance: std.Io.Threaded = .init_single_threaded;

/// Call exactly once at process startup with main's `init.io`.
pub fn install(io: std.Io) void {
    installed = io;
}

/// The process blocking Io. After `install` (production) this is the real
/// process Io; before it (tests / early bootstrap) a local fallback.
pub fn get() std.Io {
    return installed orelse fallback_instance.io();
}
