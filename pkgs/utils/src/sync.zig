const std = @import("std");

fn defaultIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub const Mutex = struct {
    inner: std.Io.Mutex = .init,

    pub const init: Mutex = .{};

    pub fn tryLock(self: *Mutex) bool {
        return self.inner.tryLock();
    }

    pub fn lock(self: *Mutex) void {
        self.inner.lockUncancelable(defaultIo());
    }

    pub fn unlock(self: *Mutex) void {
        self.inner.unlock(defaultIo());
    }
};

pub const RwLock = struct {
    inner: std.Io.RwLock = .init,

    pub const init: RwLock = .{};

    pub fn tryLock(self: *RwLock) bool {
        return self.inner.tryLock(defaultIo());
    }

    pub fn lock(self: *RwLock) void {
        self.inner.lockUncancelable(defaultIo());
    }

    pub fn unlock(self: *RwLock) void {
        self.inner.unlock(defaultIo());
    }

    pub fn tryLockShared(self: *RwLock) bool {
        return self.inner.tryLockShared(defaultIo());
    }

    pub fn lockShared(self: *RwLock) void {
        self.inner.lockSharedUncancelable(defaultIo());
    }

    pub fn unlockShared(self: *RwLock) void {
        self.inner.unlockShared(defaultIo());
    }
};
