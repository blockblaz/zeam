const std = @import("std");

const zkvm = @import("zkvm");
const ssz = @import("ssz");
const types = @import("@zeam/types");
const state_transition = @import("@zeam/state-transition");

const zeam_utils = @import("@zeam/utils");
// by default logger's activeLevel is std.log.default_level
var logger = zeam_utils.getLogger();

// TODO(gballet) move to zkvm module as each zkvm has a
// different allocated space.
var fixed_mem = [_]u8{0} ** (128 * 1024 * 1024);

// implements riscv5 runtime that runs in zkvm on provided inputs and witnesses to execute
// and prove the state transition as imported from `pkgs/state-transition`
export fn main() noreturn {
    zkvm.io.print_str("running block transition function\n");

    var prover_input: types.BeamSTFProverInput = undefined;

    var fixed_allocator = std.heap.FixedBufferAllocator.init(fixed_mem[0..]);
    const allocator = fixed_allocator.allocator();

    // Get input from memory and deserialize it
    // TODO(gballet) figure out why printing this string is necessary.
    // It might be worth commenting it once the powdr rebase has been
    // completed.
    const input = zkvm.get_input(allocator);
    defer zkvm.free_input(allocator);
    logger.debug("serialized input={any} len={d}\n", .{ input[0..], input.len });

    ssz.deserialize(types.BeamSTFProverInput, input[0..], &prover_input, allocator) catch @panic("could not deserialize input");
    logger.debug("deserialized input={any}\n", .{prover_input.state});

    // apply the state transition to modify the state
    // only print info, eventually should be dropped to .err log level
    state_transition.apply_transition(allocator, &prover_input.state, prover_input.block, .{ .activeLogLevel = .info }) catch |e| {
        logger.err("error running transition function: {any}", .{e});
    };

    logger.info("state transition completed\n", .{});

    // verify the block.state_root is ssz hash tree root of state
    // this completes our zkvm proving

    zkvm.halt(0);
}

pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    zkvm.io.print_str("PANIC: ");
    zkvm.io.print_str(msg);
    zkvm.io.print_str("\n");
    zkvm.halt(1);
    while (true) {}
}

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}
