const std = @import("std");

// Error handling utilities module
pub const ErrorHandler = struct {
    /// Get user-friendly error description
    pub fn formatError(err: anyerror) []const u8 {
        return switch (err) {
            error.FileNotFound => "File not found",
            error.AccessDenied => "Permission denied",
            error.OutOfMemory => "Out of memory",
            error.InvalidArgument => "Invalid argument",
            error.UnexpectedEndOfFile => "Unexpected end of file",
            error.FileTooBig => "File too large",
            error.DiskQuota => "Disk quota exceeded",
            error.PathAlreadyExists => "Path already exists",
            error.NoSpaceLeft => "No space left on device",
            error.IsDir => "Is a directory",
            error.NotDir => "Not a directory",
            error.NotSupported => "Operation not supported",
            error.NetworkUnreachable => "Network unreachable",
            error.ConnectionRefused => "Connection refused",
            error.ConnectionReset => "Connection reset",
            error.ConnectionTimedOut => "Connection timed out",
            error.AddressInUse => "Address already in use",
            else => @errorName(err),
        };
    }

    /// Get context-specific error message with troubleshooting hints
    pub fn getErrorContext(err: anyerror) []const u8 {
        return switch (err) {
            error.FileNotFound => "Required file or directory not found. Please check that all paths are correct.",
            error.AccessDenied => "Permission denied. Check file/directory permissions and ensure you have appropriate access.",
            error.OutOfMemory => "Insufficient memory. Try closing other applications or reducing resource usage.",
            error.InvalidArgument => "Invalid argument provided. Check command-line arguments and configuration files.",
            error.UnexpectedEndOfFile => "Unexpected end of file. Configuration file may be incomplete or corrupted.",
            error.JsonInvalidUTF8, error.JsonInvalidCharacter, error.JsonUnexpectedToken => "JSON parsing error. Check that configuration files are valid JSON.",
            error.YamlError => "YAML parsing error. Check that configuration files are valid YAML.",
            error.NetworkUnreachable, error.ConnectionRefused, error.ConnectionReset, error.ConnectionTimedOut => "Network error. Check network connectivity and that required services are running.",
            error.AddressInUse => "Port or address already in use. Try using a different port or stop the conflicting service.",
            error.NotFound => "Resource not found. Check that required files, directories, or network resources exist.",
            error.InvalidData => "Invalid data format. Check that configuration files match the expected format.",
            error.PowdrIsDeprecated => "Powdr ZKVM is deprecated. Please use risc0 or openvm instead.",
            else => "An unexpected error occurred. Check logs for more details.",
        };
    }

    /// Print formatted error message with context
    pub fn printError(err: anyerror, context: []const u8) void {
        // Suppress output during tests to avoid test framework complaints
        if (@import("builtin").is_test) return;

        std.debug.print("Error: {s}\n", .{formatError(err)});
        if (context.len > 0) {
            std.debug.print("Context: {s}\n", .{context});
        }
        std.debug.print("Error code: {s}\n\n", .{@errorName(err)});
    }

    /// Handle application-level errors with user-friendly output
    pub fn handleApplicationError(err: anyerror) void {
        // Suppress output during tests to avoid test framework complaints
        if (@import("builtin").is_test) return;

        std.debug.print("\nZeam exited with error\n\n", .{});

        const context = getErrorContext(err);
        printError(err, context);

        // Print usage hint for common argument errors
        if (err == error.InvalidArgument) {
            std.debug.print("Hint: Run 'zeam --help' or 'zeam node --help' for usage information.\n\n", .{});
        }
    }

    /// Log error with operation context (for use within mainInner)
    pub fn logErrorWithOperation(err: anyerror, comptime operation: []const u8) void {
        // Suppress output during tests to avoid test framework complaints
        if (@import("builtin").is_test) return;

        std.log.err("Failed to {s}: {s}", .{ operation, @errorName(err) });
    }

    /// Log error with operation context and additional details
    pub fn logErrorWithDetails(err: anyerror, comptime operation: []const u8, details: anytype) void {
        // Suppress output during tests to avoid test framework complaints
        if (@import("builtin").is_test) return;

        std.log.err("Failed to {s}: {s}", .{ operation, @errorName(err) });
        std.log.err("Details: {any}", .{details});
    }
};
