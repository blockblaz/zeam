const std = @import("std");
const process = std.process;
const net = std.net;
const build_options = @import("build_options");
const constants = @import("cli_constants");
const cli = @import("@zeam/cli");
const ErrorHandler = cli.error_handler.ErrorHandler;

// Central integration tests file that imports all integration test modules.
// This file serves as the entry point for the "simtest" build step.
//
// Integration tests imported here:
// - beam_integration_test.zig: Beam command and SSE events integration tests
// - genesis_to_finalization_test.zig: Two-node genesis to finalization simulation test
// - lean_quickstart_integration_test.zig: Full lean-quickstart integration test (Option B)
//
// Run with: zig build simtest

test {
    // Import beam command integration tests (CLI with mock network, SSE events)
    _ = @import("beam_integration_test.zig");

    // Import genesis to finalization integration test (two nodes in-process)
    _ = @import("genesis_to_finalization_test.zig");

    // Import lean-quickstart full integration test (Option B implementation)
    _ = @import("lean_quickstart_integration_test.zig");
}

// Test suite for ErrorHandler
test "ErrorHandler.formatError - known errors" {
    const testing = std.testing;

    try testing.expectEqualStrings("File not found", ErrorHandler.formatError(error.FileNotFound));
    try testing.expectEqualStrings("Permission denied", ErrorHandler.formatError(error.AccessDenied));
    try testing.expectEqualStrings("Out of memory", ErrorHandler.formatError(error.OutOfMemory));
    try testing.expectEqualStrings("Invalid argument", ErrorHandler.formatError(error.InvalidArgument));
    try testing.expectEqualStrings("Network unreachable", ErrorHandler.formatError(error.NetworkUnreachable));
    try testing.expectEqualStrings("Connection refused", ErrorHandler.formatError(error.ConnectionRefused));
    try testing.expectEqualStrings("Address already in use", ErrorHandler.formatError(error.AddressInUse));
    try testing.expectEqualStrings("File too large", ErrorHandler.formatError(error.FileTooBig));
}

test "ErrorHandler.formatError - unknown error falls back to error name" {
    const testing = std.testing;
    // Create a test error set with a unique error
    const TestError = error{
        TestUniqueError,
    };

    const result = ErrorHandler.formatError(TestError.TestUniqueError);
    // Should return the error name since it's not in our switch
    try testing.expect(std.mem.eql(u8, result, "TestUniqueError"));
}

test "ErrorHandler.getErrorContext - provides helpful context for known errors" {
    const testing = std.testing;

    const fileNotFoundContext = ErrorHandler.getErrorContext(error.FileNotFound);
    try testing.expect(fileNotFoundContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, fileNotFoundContext, 1, "file"));

    const invalidArgContext = ErrorHandler.getErrorContext(error.InvalidArgument);
    try testing.expect(invalidArgContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, invalidArgContext, 1, "argument"));

    const networkContext = ErrorHandler.getErrorContext(error.NetworkUnreachable);
    try testing.expect(networkContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, networkContext, 1, "network"));

    const jsonContext = ErrorHandler.getErrorContext(error.JsonInvalidUTF8);
    try testing.expect(jsonContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, jsonContext, 1, "JSON"));

    const yamlContext = ErrorHandler.getErrorContext(error.YamlError);
    try testing.expect(yamlContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, yamlContext, 1, "YAML"));

    const powdrContext = ErrorHandler.getErrorContext(error.PowdrIsDeprecated);
    try testing.expect(powdrContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, powdrContext, 1, "deprecated"));
}

test "ErrorHandler.getErrorContext - handles multiple JSON error types" {
    const testing = std.testing;

    // All JSON errors should return the same context
    const context1 = ErrorHandler.getErrorContext(error.JsonInvalidUTF8);
    const context2 = ErrorHandler.getErrorContext(error.JsonInvalidCharacter);
    const context3 = ErrorHandler.getErrorContext(error.JsonUnexpectedToken);

    try testing.expectEqualStrings(context1, context2);
    try testing.expectEqualStrings(context2, context3);
    try testing.expect(std.mem.containsAtLeast(u8, context1, 1, "JSON"));
}

test "ErrorHandler.getErrorContext - handles multiple network error types" {
    const testing = std.testing;

    // All network errors should return the same context
    const context1 = ErrorHandler.getErrorContext(error.NetworkUnreachable);
    const context2 = ErrorHandler.getErrorContext(error.ConnectionRefused);
    const context3 = ErrorHandler.getErrorContext(error.ConnectionReset);
    const context4 = ErrorHandler.getErrorContext(error.ConnectionTimedOut);

    try testing.expectEqualStrings(context1, context2);
    try testing.expectEqualStrings(context2, context3);
    try testing.expectEqualStrings(context3, context4);
    try testing.expect(std.mem.containsAtLeast(u8, context1, 1, "network"));
}

test "ErrorHandler.getErrorContext - unknown error provides generic message" {
    const testing = std.testing;

    const TestError = error{
        UnknownTestError,
    };

    const context = ErrorHandler.getErrorContext(TestError.UnknownTestError);
    try testing.expect(std.mem.containsAtLeast(u8, context, 1, "unexpected"));
}

test "ErrorHandler.printError - formats error correctly" {
    // This test verifies printError doesn't crash
    // We can't easily capture stderr in Zig tests without more complex setup
    ErrorHandler.printError(error.FileNotFound, "Test context message");
    // If we get here without a crash, the function works
}

test "ErrorHandler.handleApplicationError - handles InvalidArgument with hint" {
    // This test verifies handleApplicationError doesn't crash
    // The hint for InvalidArgument is included in the function
    ErrorHandler.handleApplicationError(error.InvalidArgument);
    // If we get here without a crash, the function works
}

test "ErrorHandler.handleApplicationError - handles various error types" {
    // Test that handleApplicationError works for different error types
    ErrorHandler.handleApplicationError(error.FileNotFound);
    ErrorHandler.handleApplicationError(error.AccessDenied);
    ErrorHandler.handleApplicationError(error.OutOfMemory);
    ErrorHandler.handleApplicationError(error.NetworkUnreachable);
    ErrorHandler.handleApplicationError(error.PowdrIsDeprecated);

    // Test unknown error
    const TestError = error{UnknownError};
    ErrorHandler.handleApplicationError(TestError.UnknownError);

    // If we get here without a crash, all error types are handled
}

test "ErrorHandler.logErrorWithOperation - logs operation context" {
    // This test verifies the function doesn't crash
    // Actual logging output would need to be captured differently
    ErrorHandler.logErrorWithOperation(error.FileNotFound, "test operation");
    // If we get here without a crash, the function works
}

test "ErrorHandler.logErrorWithDetails - logs error with details" {
    // This test verifies the function doesn't crash with various detail types
    ErrorHandler.logErrorWithDetails(error.FileNotFound, "test operation", .{ .path = "/test/path" });
    ErrorHandler.logErrorWithDetails(error.AddressInUse, "start server", .{ .port = 8080 });
    ErrorHandler.logErrorWithDetails(error.ConnectionRefused, "connect", .{ .address = "127.0.0.1", .port = 9001 });
    // If we get here without a crash, the function works with different detail types
}

test "ErrorHandler - comprehensive error coverage" {
    const testing = std.testing;

    // Test all major error categories have both formatError and getErrorContext
    const test_errors = [_]anyerror{
        error.FileNotFound,
        error.AccessDenied,
        error.OutOfMemory,
        error.InvalidArgument,
        error.UnexpectedEndOfFile,
        error.FileTooBig,
        error.DiskQuota,
        error.PathAlreadyExists,
        error.NoSpaceLeft,
        error.IsDir,
        error.NotDir,
        error.NotSupported,
        error.NetworkUnreachable,
        error.ConnectionRefused,
        error.ConnectionReset,
        error.ConnectionTimedOut,
        error.AddressInUse,
        error.NotFound,
        error.InvalidData,
        error.JsonInvalidUTF8,
        error.JsonInvalidCharacter,
        error.JsonUnexpectedToken,
        error.YamlError,
        error.PowdrIsDeprecated,
    };

    for (test_errors) |err| {
        const formatted = ErrorHandler.formatError(err);
        try testing.expect(formatted.len > 0);

        const context = ErrorHandler.getErrorContext(err);
        try testing.expect(context.len > 0);

        // Both should not be empty
        try testing.expect(!std.mem.eql(u8, formatted, ""));
        try testing.expect(!std.mem.eql(u8, context, ""));
    }
}
