const std = @import("std");

const skip_env_var_name = "ZEAM_SPECTEST_SKIP_EXPECTED_ERRORS";

const AtomicBool = std.atomic.Value(bool);

var flag = AtomicBool.init(false);
var manual_override = AtomicBool.init(false);
var env_once = std.once(initializeFromEnv);

fn detectSkipFlagFromEnv() bool {
    const env_val = std.process.getEnvVarOwned(std.heap.page_allocator, skip_env_var_name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        error.InvalidWtf8 => return false,
        error.OutOfMemory => @panic("unable to allocate while reading spectest skip env var"),
    };
    defer std.heap.page_allocator.free(env_val);

    const trimmed = std.mem.trim(u8, env_val, &std.ascii.whitespace);
    return std.mem.eql(u8, trimmed, "true") or std.mem.eql(u8, trimmed, "1");
}

fn initializeFromEnv() void {
    if (manual_override.load(.seq_cst)) return;
    flag.store(detectSkipFlagFromEnv(), .seq_cst);
}

pub fn configured() bool {
    if (!manual_override.load(.seq_cst)) {
        env_once.call();
    }
    return flag.load(.seq_cst);
}

pub fn set(value: bool) void {
    manual_override.store(true, .seq_cst);
    flag.store(value, .seq_cst);
}

pub fn name() []const u8 {
    return skip_env_var_name;
}
