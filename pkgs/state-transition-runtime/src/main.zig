const std = @import("std");

const zkvm = @import("zkvm");
const ssz = @import("ssz");
const types = @import("@zeam/types");
const state_transition = @import("@zeam/state-transition");

var fixed_mem = [_]u8{0} ** (256 * 1024 * 1024);

const Inputs = struct {
    state_root: []const u8,
    block_root: []const u8,
};

const Witnesses = struct {
    state: []const u8,
    block: []const u8,
};

// implements risv5 runtime that runs in zkvm on provided inputs and witnesses to execute
// and prove the state transition as imported from `pkgs/state-transition`
export fn main() noreturn {
    zkvm.io.print_str("running block transition function\n");
    // access inputs and witnesses from zkvm
    const inputs = Inputs{
        .state_root = &[_]u8{},
        .block_root = &[_]u8{},
    };
    _ = inputs;
    const witnesses = Witnesses{
        .state = &[_]u8{},
        .block = &[_]u8{},
    };
    _ = witnesses;

    var fixed_allocator = std.heap.FixedBufferAllocator.init(fixed_mem[0..]);
    const allocator = fixed_allocator.allocator();

    // TODO: construct state and block from witnesses and validate stateroot and block root
    // use the ssz deserialized state and block to apply state transition

    var state: types.BeamState = undefined;
    const block: types.SignedBeamBlock = undefined;

    // get some allocator
    // apply the state transition to modify the state
    state_transition.apply_transition(allocator, &state, block) catch @panic("error running transition function");

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
