const std = @import("std");
const Allocator = std.mem.Allocator;
const Yaml = @import("yaml").Yaml;

const max_file_size = 1024 * 1024; // 1MB

/// Load and parse a YAML file from the given file path.
/// The file path can be absolute or relative to the current working directory.
/// Returns a `Yaml` struct containing the parsed content.
/// The caller is responsible for freeing the resources associated with the `Yaml` struct.
pub fn loadFromYAMLFile(allocator: Allocator, file_path: []const u8) !Yaml {
    const resolved_path = if (std.fs.path.isAbsolute(file_path))
        try allocator.dupe(u8, file_path)
    else
        try std.fs.cwd().realpathAlloc(allocator, file_path);
    defer allocator.free(resolved_path);

    const file = try std.fs.openFileAbsolute(resolved_path, .{});
    defer file.close();

    if (try file.getEndPos() > max_file_size) {
        return error.FileTooLarge;
    }

    const source = try file.readToEndAlloc(allocator, max_file_size);
    defer allocator.free(source);

    var yaml: Yaml = .{ .source = source };
    errdefer yaml.deinit(allocator);
    try yaml.load(allocator);
    return yaml;
}
