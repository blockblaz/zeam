const std = @import("std");

/// Checks if a directory exists at the given path.
/// The path can be absolute or relative to the current working directory.
/// Returns an error if the directory does not exist or cannot be opened.
pub fn checkDIRExists(path: []const u8) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.isAbsolute(path)) {
        const dir = try std.Io.Dir.openDirAbsolute(io, path, .{});
        dir.close(io);
    } else {
        const dir = try std.Io.Dir.cwd().openDir(io, path, .{});
        dir.close(io);
    }
}

/// Reads the entire content of a file at the given path into a byte slice.
/// The path can be absolute or relative to the current working directory.
/// The caller is responsible for freeing the returned byte slice.
/// `max_bytes` limits the maximum number of bytes to read to prevent excessive memory usage.
pub fn readFileToEndAlloc(allocator: std.mem.Allocator, file_path: []const u8, max_bytes: usize) ![]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(max_bytes));
}

test "checkDIRExists with absolute path" {
    try checkDIRExists("/");
}

test "checkDIRExists with relative path" {
    try checkDIRExists(".");
}

test "checkDIRExists with created directory" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const test_dir = "fs_test_dir";
    try std.Io.Dir.cwd().createDirPath(io, test_dir);
    defer std.Io.Dir.cwd().deleteDir(io, test_dir) catch {};

    try checkDIRExists(test_dir);
}

test "checkDIRExists with non-existent directory" {
    const result = checkDIRExists("definitely_does_not_exist_12345");
    try std.testing.expectError(error.FileNotFound, result);
}

test "readFileToEndAlloc with relative path" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const test_file = "test_read_relative.txt";
    const test_content = "Hello from relative path!";

    const file = try std.Io.Dir.cwd().createFile(io, test_file, .{});
    var write_buf: [test_content.len]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll(test_content);
    try writer.interface.flush();
    file.close(io);
    defer std.Io.Dir.cwd().deleteFile(io, test_file) catch {};

    const content = try readFileToEndAlloc(std.testing.allocator, test_file, 1024);
    defer std.testing.allocator.free(content);

    try std.testing.expectEqualStrings(test_content, content);
}

test "readFileToEndAlloc with absolute path" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const abs_test_file = "/tmp/test_read_absolute.txt";
    const test_content = "Hello from absolute path!";

    const file = try std.Io.Dir.createFileAbsolute(io, abs_test_file, .{ .truncate = true });
    var write_buf: [test_content.len]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll(test_content);
    try writer.interface.flush();
    file.close(io);
    defer std.Io.Dir.deleteFileAbsolute(io, abs_test_file) catch {};

    const content = try readFileToEndAlloc(std.testing.allocator, abs_test_file, 1024);
    defer std.testing.allocator.free(content);

    try std.testing.expectEqualStrings(test_content, content);
}

test "readFileToEndAlloc with non-existent file" {
    const result = readFileToEndAlloc(std.testing.allocator, "non_existent_file.txt", 1024);
    try std.testing.expectError(error.FileNotFound, result);
}
