const std = @import("std");

const skip_env_var_name = "ZEAM_SPECTEST_SKIP_EXPECTED_ERRORS";

var flag: bool = false;
var initialized: bool = false;

fn detectSkipFlagFromEnv() bool {
    std.debug.assert(!initialized);

    const env_val = std.process.getEnvVarOwned(std.heap.page_allocator, skip_env_var_name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        error.InvalidWtf8 => return false,
        error.OutOfMemory => @panic("unable to allocate while reading spectest skip env var"),
    };
    defer std.heap.page_allocator.free(env_val);

    const trimmed = std.mem.trim(u8, env_val, &std.ascii.whitespace);
    return std.mem.eql(u8, trimmed, "true") or std.mem.eql(u8, trimmed, "1");
}

pub fn configured() bool {
    if (!initialized) {
        const detected_flag = detectSkipFlagFromEnv();
        set(detected_flag);
    }
    return flag;
}

pub fn set(value: bool) void {
    flag = value;
    initialized = true;
}

pub fn name() []const u8 {
    return skip_env_var_name;
}
