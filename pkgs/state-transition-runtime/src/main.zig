const std = @import("std");

const zkvm = @import("zkvm");
const ssz = @import("ssz");
const types = @import("zeam-types");
const state_transition = @import("zeam-state-transition");

var fixed_mem = [_]u8{0} ** (256 * 1024 * 1024);

// implements risv5 runtime that runs in zkvm on provided inputs and witnesses to execute
// and prove the state transition as imported from `pkgs/state-transition`
export fn main() noreturn {
    zkvm.io.print_str("running block transition function\n");

    var fixed_allocator = std.heap.FixedBufferAllocator.init(fixed_mem[0..]);
    const allocator = fixed_allocator.allocator();

    // Temporary interface: get bytes as u32 and turn it into a byte slice
    const serialized_block_len = zkvm.io.read_data_len(0);
    var serialized_block_u32 = allocator.alloc(u32, serialized_block_len) catch @panic("allocating u32 serialized block slice");
    defer allocator.free(serialized_block_u32);
    zkvm.io.read_slice(0, serialized_block_u32[0..]);
    var serialized_block_bytes = allocator.alloc(u8, serialized_block_len) catch @panic("allocating serialized block slice");
    defer allocator.free(serialized_block_bytes);
    for (serialized_block_u32, 0..) |word, i| {
        serialized_block_bytes[i] = @truncate(word);
    }

    var prover_input: types.BeamSTFProverInput = undefined;

    ssz.deserialize(types.BeamSTFProverInput, serialized_block_bytes, &prover_input, allocator) catch @panic("error deserializing block");

    // get some allocator
    // apply the state transition to modify the state
    state_transition.apply_transition(allocator, &prover_input.state, prover_input.block) catch @panic("error running transition function");

    // verify the block.state_root is ssz hash tree root of state
    // this completes our zkvm proving
    var root_hash: [32]u8 = undefined;
    ssz.hashTreeRoot(types.BeamState, prover_input.state, &root_hash, allocator) catch @panic("error hashing the root state");

    zkvm.halt(0);
}

pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    zkvm.io.print_str("PANIC: ");
    zkvm.io.print_str(msg);
    zkvm.io.print_str("\n");
    zkvm.halt(1);
    while (true) {}
}
