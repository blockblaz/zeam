const std = @import("std");

/// Checks if a directory exists at the given path.
/// The path can be absolute or relative to the current working directory.
/// Returns an error if the directory does not exist or cannot be opened.
pub fn checkDIRExists(path: []const u8) !void {
    if (std.fs.path.isAbsolute(path)) {
        var dir = try std.fs.openDirAbsolute(path, .{});
        defer dir.close();
    } else {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
    }
}

/// Reads the entire content of a file at the given path into a byte slice.
/// The path can be absolute or relative to the current working directory.
/// The caller is responsible for freeing the returned byte slice.
/// `max_bytes` limits the maximum number of bytes to read to prevent excessive memory usage.
pub fn readFileToEndAlloc(allocator: std.mem.Allocator, file_path: []const u8, max_bytes: usize) ![]u8 {
    const resolved_path = if (std.fs.path.isAbsolute(file_path))
        try allocator.dupe(u8, file_path)
    else
        try std.fs.cwd().realpathAlloc(allocator, file_path);
    defer allocator.free(resolved_path);

    const file = try std.fs.openFileAbsolute(resolved_path, .{});
    defer file.close();

    return try file.readToEndAlloc(allocator, max_bytes);
}

test "checkDIRExists with absolute path" {
    const cwd_path = try std.fs.cwd().realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_path);

    try checkDIRExists(cwd_path);
}

test "checkDIRExists with relative path" {
    try checkDIRExists(".");
}

test "checkDIRExists with created directory" {
    const test_dir = "fs_test_dir";
    try std.fs.cwd().makeDir(test_dir);
    defer std.fs.cwd().deleteDir(test_dir) catch {};

    try checkDIRExists(test_dir);
}

test "checkDIRExists with non-existent directory" {
    const result = checkDIRExists("definitely_does_not_exist_12345");
    try std.testing.expectError(error.FileNotFound, result);
}

test "readFileToEndAlloc with relative path" {
    const test_file = "test_read_relative.txt";
    const test_content = "Hello from relative path!";

    const file = try std.fs.cwd().createFile(test_file, .{});
    try file.writeAll(test_content);
    file.close();
    defer std.fs.cwd().deleteFile(test_file) catch {};

    const content = try readFileToEndAlloc(std.testing.allocator, test_file, 1024);
    defer std.testing.allocator.free(content);

    try std.testing.expectEqualStrings(test_content, content);
}

test "readFileToEndAlloc with absolute path" {
    const test_file = "test_read_absolute.txt";
    const test_content = "Hello from absolute path!";

    const file = try std.fs.cwd().createFile(test_file, .{});
    try file.writeAll(test_content);
    file.close();
    defer std.fs.cwd().deleteFile(test_file) catch {};

    const abs_path = try std.fs.cwd().realpathAlloc(std.testing.allocator, test_file);
    defer std.testing.allocator.free(abs_path);

    const content = try readFileToEndAlloc(std.testing.allocator, abs_path, 1024);
    defer std.testing.allocator.free(content);

    try std.testing.expectEqualStrings(test_content, content);
}

test "readFileToEndAlloc with non-existent file" {
    const result = readFileToEndAlloc(std.testing.allocator, "non_existent_file.txt", 1024);
    try std.testing.expectError(error.FileNotFound, result);
}
