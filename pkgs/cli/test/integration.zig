const std = @import("std");

// Central integration tests file that imports all integration test modules.
// This file serves as the entry point for the "simtest" build step.
//
// Integration tests imported here:
// - beam_integration_test.zig: Beam command and SSE events integration tests
// - genesis_to_finalization_test.zig: Two-node genesis to finalization simulation test
//
// Run with: zig build simtest

test {
    // Import beam command integration tests (CLI with mock network, SSE events)
    _ = @import("beam_integration_test.zig");

    // Import genesis to finalization integration test (two nodes in-process)
    _ = @import("genesis_to_finalization_test.zig");
}
