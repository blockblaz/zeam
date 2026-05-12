const std = @import("std");

const skip_env_var_name = "ZEAM_SPECTEST_SKIP_EXPECTED_ERRORS";

const AtomicBool = std.atomic.Value(bool);

var flag = AtomicBool.init(false);
var manual_override = AtomicBool.init(false);
// `std.once` was removed in Zig 0.16. Replicate the once-call semantics with
// a small atomic CAS: the first caller wins, runs the initialiser, then
// flips `env_done` to .seq_cst so subsequent callers fall through.
var env_started = AtomicBool.init(false);
var env_done = AtomicBool.init(false);

fn detectSkipFlagFromEnv() bool {
    // Zig 0.16 removed `std.process.getEnvVarOwned`; env access now goes
    // through `std.process.Environ`. In test context we can read the
    // `std.testing.environ` instance that the test runner initialises.
    // Outside tests this code path is unreachable (skip.zig is only ever
    // consulted by the spectest harness, which runs inside `zig test`).
    if (!@import("builtin").is_test) return false;
    const env_val = std.testing.environ.getPosix(skip_env_var_name) orelse return false;
    const trimmed = std.mem.trim(u8, env_val, &std.ascii.whitespace);
    return std.mem.eql(u8, trimmed, "true") or std.mem.eql(u8, trimmed, "1");
}

fn initializeFromEnv() void {
    if (manual_override.load(.seq_cst)) return;
    flag.store(detectSkipFlagFromEnv(), .seq_cst);
}

pub fn configured() bool {
    if (!manual_override.load(.seq_cst)) {
        // Run env init exactly once. CAS guards the first caller; later
        // callers spin briefly waiting for env_done so they observe the
        // initialised flag.
        if (env_started.cmpxchgStrong(false, true, .seq_cst, .seq_cst) == null) {
            initializeFromEnv();
            env_done.store(true, .seq_cst);
        } else {
            while (!env_done.load(.seq_cst)) std.atomic.spinLoopHint();
        }
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
