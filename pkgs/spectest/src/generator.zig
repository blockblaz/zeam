const std = @import("std");
const forks = @import("fork.zig");
const fixture_kind = @import("fixture_kind.zig");

const FixtureKind = fixture_kind.FixtureKind;
const all_kinds = fixture_kind.all;

const Allocator = std.mem.Allocator;
const usage =
    "Usage:\n" ++
    "  zig build spectest:generate -- [options]\n" ++
    "  zig run pkgs/spectest/src/generator.zig -- [options]\n" ++
    "\n" ++
    "Options:\n" ++
    "  --vectors-root <path>   Root directory containing fixture JSON (default leanSpec/fixtures)\n" ++
    "  --output <path>         Output path for generated tests (default pkgs/spectest/src/generated)\n" ++
    "  --dry-run               List discovered fixtures without writing the file\n" ++
    "  -h, --help              Show this message\n";

const default_vectors_root = "leanSpec/fixtures";
const default_output_path = "pkgs/spectest/src/generated";

const FixtureRoute = struct {
    kind: FixtureKind,
    fork_name: []const u8,
    fork_symbol: []const u8,
    suite: []const u8,
    handler: []const u8,
    case_name: []const u8,
};

const GroupedEntry = struct {
    rel_path: []const u8,
    route: FixtureRoute,
};

const HandlerGroup = struct {
    handler_name: []u8,
    entries: std.ArrayList(GroupedEntry),
};

const SuiteGroup = struct {
    suite_name: []u8,
    handlers: std.ArrayList(HandlerGroup),
};

const ForkGroup = struct {
    kind: FixtureKind,
    fork_name: []u8,
    fork_symbol: []u8,
    suites: std.ArrayList(SuiteGroup),
};

const WriteSummary = struct {
    emitted_count: usize,
    file_count: usize,
};

const CliOptions = struct {
    allocator: Allocator,
    vectors_root: []u8,
    vectors_root_explicit: bool,
    output_path: []u8,
    dry_run: bool,

    fn deinit(self: *CliOptions) void {
        self.allocator.free(self.vectors_root);
        self.allocator.free(self.output_path);
    }
};

fn parseArgs(allocator: Allocator, argv: []const [:0]u8) !CliOptions {
    var options = CliOptions{
        .allocator = allocator,
        .vectors_root = try allocator.dupe(u8, default_vectors_root),
        .vectors_root_explicit = false,
        .output_path = try allocator.dupe(u8, default_output_path),
        .dry_run = false,
    };

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = std.mem.sliceTo(argv[i], 0);
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("{s}\n", .{usage});
            options.deinit();
            return error.DisplayHelp;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            options.dry_run = true;
        } else if (std.mem.eql(u8, arg, "--vectors-root")) {
            i += 1;
            if (i >= argv.len) {
                std.debug.print("spectest: missing value for --vectors-root\n\n{s}\n", .{usage});
                options.deinit();
                return error.InvalidArgument;
            }
            options.allocator.free(options.vectors_root);
            const value = std.mem.sliceTo(argv[i], 0);
            options.vectors_root = try allocator.dupe(u8, value);
            options.vectors_root_explicit = true;
        } else if (std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= argv.len) {
                std.debug.print("spectest: missing value for --output\n\n{s}\n", .{usage});
                options.deinit();
                return error.InvalidArgument;
            }
            options.allocator.free(options.output_path);
            const value = std.mem.sliceTo(argv[i], 0);
            options.output_path = try allocator.dupe(u8, value);
        } else {
            std.debug.print("spectest: unknown argument {s}\n\n{s}\n", .{ arg, usage });
            options.deinit();
            return error.InvalidArgument;
        }
    }

    return options;
}

fn dirExists(path: []const u8) bool {
    const result = if (std.fs.path.isAbsolute(path))
        std.fs.openDirAbsolute(path, .{})
    else
        std.fs.cwd().openDir(path, .{});
    return result catch null != null;
}

fn ensureVectorsRoot(options: *CliOptions) !void {
    if (dirExists(options.vectors_root)) return;
    if (!options.vectors_root_explicit) {
        std.debug.print(
            "spectest: unable to locate fixtures at default path {s}\n",
            .{options.vectors_root},
        );
    }
    return error.FixtureRootNotFound;
}

fn collectFixtures(allocator: Allocator, root_path: []const u8) ![][]const u8 {
    var list = std.ArrayList([]const u8).empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }

    const dir_result = if (std.fs.path.isAbsolute(root_path))
        std.fs.openDirAbsolute(root_path, .{ .iterate = true })
    else
        std.fs.cwd().openDir(root_path, .{ .iterate = true });

    var dir = dir_result catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return error.FixtureRootNotFound,
        else => return err,
    };
    defer dir.close();

    try walkDir(allocator, "", &dir, &list);

    const fixtures = try list.toOwnedSlice(allocator);
    std.mem.sort([]const u8, fixtures, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.lessThan);
    return fixtures;
}

fn walkDir(
    allocator: Allocator,
    rel_dir: []const u8,
    dir: *std.fs.Dir,
    list: *std.ArrayList([]const u8),
) !void {
    var it = dir.iterate();
    while (true) {
        const entry = try it.next();
        if (entry == null) break;
        const item = entry.?;

        const child_rel = try joinRelative(allocator, rel_dir, item.name);
        defer allocator.free(child_rel);

        switch (item.kind) {
            .directory => {
                var child_dir = dir.openDir(item.name, .{ .iterate = true }) catch |err| switch (err) {
                    error.NotDir => continue,
                    else => return err,
                };
                defer child_dir.close();
                try walkDir(allocator, child_rel, &child_dir, list);
            },
            .file => {
                if (!std.mem.endsWith(u8, child_rel, ".json")) continue;
                if (std.mem.eql(u8, item.name, "VERSION.json")) continue;
                try list.append(allocator, try allocator.dupe(u8, child_rel));
            },
            else => {},
        }
    }
}

fn joinRelative(allocator: Allocator, prefix: []const u8, name: []const u8) ![]u8 {
    if (prefix.len == 0) return allocator.dupe(u8, name);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, name });
}

fn parseKindSegment(segment: []const u8) ?FixtureKind {
    inline for (all_kinds) |kind| {
        if (std.mem.eql(u8, kind.runnerModule(), segment)) return kind;
    }
    return null;
}

fn parseFixtureRoute(rel_path: []const u8) !FixtureRoute {
    var it = std.mem.tokenizeScalar(u8, rel_path, '/');

    const root = it.next() orelse return error.InvalidFixturePath;
    if (!std.mem.eql(u8, root, "consensus")) return error.UnsupportedFixture;

    const kind_segment = it.next() orelse return error.InvalidFixturePath;
    const kind = parseKindSegment(kind_segment) orelse return error.UnsupportedFixture;

    const fork_segment = it.next() orelse return error.InvalidFixturePath;
    const fork = forks.findByPath(fork_segment) orelse return error.UnsupportedFork;

    const suite_segment = it.next() orelse return error.InvalidFixturePath;
    const handler_segment = it.next() orelse return error.InvalidFixturePath;
    const file_name = it.next() orelse return error.InvalidFixturePath;
    if (it.next() != null) return error.InvalidFixturePath;

    if (!std.mem.endsWith(u8, file_name, ".json")) return error.UnsupportedFixture;
    const case_name = file_name[0 .. file_name.len - ".json".len];

    return FixtureRoute{
        .kind = kind,
        .fork_name = fork_segment,
        .fork_symbol = fork.symbol,
        .suite = suite_segment,
        .handler = handler_segment,
        .case_name = case_name,
    };
}

fn makeRunnerPrefix(allocator: Allocator, levels_up: usize) ![]u8 {
    if (levels_up == 0) return allocator.alloc(u8, 0);
    var list = std.ArrayList(u8).empty;
    errdefer list.deinit(allocator);
    try list.ensureTotalCapacityPrecise(allocator, levels_up * 3);
    for (0..levels_up) |_| try list.appendSlice(allocator, "../");
    return list.toOwnedSlice(allocator);
}

fn countPathSegments(path: []const u8) usize {
    if (path.len == 0) return 0;
    if (std.mem.eql(u8, path, ".")) return 0;
    var it = std.mem.tokenizeScalar(u8, path, '/');
    var count: usize = 0;
    while (it.next()) |_| count += 1;
    return count;
}

fn computeLevelsUp(from_dir: []const u8, target_dir: []const u8) usize {
    const from_segments = countPathSegments(from_dir);
    const target_segments = countPathSegments(target_dir);
    if (from_segments <= target_segments) return 0;
    return from_segments - target_segments;
}

fn makeHeaderWithPrefix(allocator: Allocator, prefix: []const u8, kind: FixtureKind) ![]u8 {
    var list = std.ArrayList(u8).empty;
    errdefer list.deinit(allocator);
    var writer = list.writer(allocator);

    try writer.writeAll("// This file is generated by pkgs/spectest/src/generator.zig.\n");
    try writer.writeAll("// Do not edit manually.\n\n");
    try writer.writeAll("const std = @import(\"std\");\n");
    try writer.print("const forks = @import(\"{s}fork.zig\");\n", .{prefix});
    const runner_module = kind.runnerModule();
    try writer.print(
        "const {s} = @import(\"{s}runner/{s}_runner.zig\");\n",
        .{ runner_module, prefix, runner_module },
    );
    try writer.print("const skip = @import(\"{s}skip.zig\");\n\n", .{prefix});
    try writer.writeAll("const test_allocator = std.testing.allocator;\n");
    try writer.writeAll("const fixture_root_candidate = \"leanSpec/fixtures\";\n\n");
    try writer.writeAll("const ResolveError = error{\n    FixturesNotFound,\n};\n\n");
    try writer.writeAll("fn resolveFixturesRoot(allocator: std.mem.Allocator) ResolveError![]u8 {\n");
    try writer.writeAll("    const cwd = std.fs.cwd();\n");
    try writer.writeAll("    const resolved = cwd.realpathAlloc(allocator, fixture_root_candidate) catch {\n");
    try writer.writeAll("        std.debug.print(\n");
    try writer.writeAll("            \"spectest: unable to locate leanSpec fixtures at {s}\\n\",\n");
    try writer.writeAll("            .{fixture_root_candidate},\n");
    try writer.writeAll("        );\n");
    try writer.writeAll("        return ResolveError.FixturesNotFound;\n");
    try writer.writeAll("    };\n");
    try writer.writeAll("    return resolved;\n}\n\n");

    try writer.writeAll("var skip_cli_initialized = false;\n\n");
    try writer.writeAll("fn configureSkipBehaviour() void {\n");
    try writer.writeAll("    _ = skip.configured();\n");
    try writer.writeAll("    if (skip_cli_initialized) return;\n");
    try writer.writeAll("    if (parseSkipOverrideFromArgs()) |override| {\n");
    try writer.writeAll("        skip.set(override);\n");
    try writer.writeAll("    }\n");
    try writer.writeAll("    skip_cli_initialized = true;\n");
    try writer.writeAll("}\n\n");
    try writer.writeAll("fn parseSkipOverrideFromArgs() ?bool {\n");
    try writer.writeAll("    const allocator = std.heap.page_allocator;\n");
    try writer.writeAll("    const argv = std.process.argsAlloc(allocator) catch return null;\n");
    try writer.writeAll("    defer std.process.argsFree(allocator, argv);\n");
    try writer.writeAll("    var override: ?bool = null;\n");
    try writer.writeAll("    for (argv) |arg_z| {\n");
    try writer.writeAll("        const arg = std.mem.sliceTo(arg_z, 0);\n");
    try writer.writeAll("        if (std.mem.eql(u8, arg, \"--skip-expected-error-fixtures\")) {\n");
    try writer.writeAll("            override = true;\n");
    try writer.writeAll("        } else if (std.mem.startsWith(u8, arg, \"--skip-expected-error-fixtures=\")) {\n");
    try writer.writeAll("            const value = arg[\"--skip-expected-error-fixtures=\".len..];\n");
    try writer.writeAll("            override = parseBool(value);\n");
    try writer.writeAll("        }\n");
    try writer.writeAll("    }\n");
    try writer.writeAll("    return override;\n}\n\n");
    try writer.writeAll("fn parseBool(raw: []const u8) bool {\n");
    try writer.writeAll("    const trimmed = std.mem.trim(u8, raw, \" \\t\\r\\n\");\n");
    try writer.writeAll("    if (trimmed.len == 0) return true;\n");
    try writer.writeAll("    if (equalsIgnoreCase(trimmed, \"true\")) return true;\n");
    try writer.writeAll("    if (equalsIgnoreCase(trimmed, \"false\")) return false;\n");
    try writer.writeAll("    return true;\n}\n\n");
    try writer.writeAll("fn equalsIgnoreCase(lhs: []const u8, rhs: []const u8) bool {\n");
    try writer.writeAll("    if (lhs.len != rhs.len) return false;\n");
    try writer.writeAll("    for (lhs, rhs) |a, b| {\n");
    try writer.writeAll("        if (std.ascii.toLower(a) != std.ascii.toLower(b)) return false;\n");
    try writer.writeAll("    }\n");
    try writer.writeAll("    return true;\n}\n\n");

    return list.toOwnedSlice(allocator);
}

fn makeLiteral(allocator: Allocator, text: []const u8) ![]u8 {
    var list = std.ArrayList(u8).empty;
    errdefer list.deinit(allocator);
    var writer = list.writer(allocator);
    try writer.writeByte('"');
    for (text) |byte| {
        switch (byte) {
            '\\' => try writer.writeAll("\\\\"),
            '"' => try writer.writeAll("\\\""),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (byte < 0x20 or byte == 0x7f) {
                    const hex_digits = "0123456789abcdef";
                    try writer.writeAll("\\x");
                    try writer.writeByte(hex_digits[byte >> 4]);
                    try writer.writeByte(hex_digits[byte & 0x0f]);
                } else {
                    try writer.writeByte(byte);
                }
            },
        }
    }
    try writer.writeByte('"');
    return list.toOwnedSlice(allocator);
}

fn writeTestCase(
    writer: anytype,
    label_literal: []const u8,
    runner_module: []const u8,
    fork_symbol: []const u8,
    path_literal: []const u8,
) !void {
    try writer.print("test {s} {{\n", .{label_literal});
    try writer.writeAll("    configureSkipBehaviour();\n");
    try writer.writeAll("    const fixtures_path = resolveFixturesRoot(test_allocator) catch |err| switch (err) {\n");
    try writer.writeAll("        ResolveError.FixturesNotFound => return error.SkipZigTest,\n");
    try writer.writeAll("        else => return err,\n");
    try writer.writeAll("    };\n");
    try writer.writeAll("    defer test_allocator.free(fixtures_path);\n");
    try writer.writeAll("    var fixtures_dir = std.fs.openDirAbsolute(fixtures_path, .{}) catch |err| {\n");
    try writer.writeAll("        std.debug.print(\n");
    try writer.writeAll("            \"spectest: failed to open fixtures root {s}: {s}\\n\",\n");
    try writer.writeAll("            .{ fixtures_path, @errorName(err) },\n");
    try writer.writeAll("        );\n");
    try writer.writeAll("        return err;\n");
    try writer.writeAll("    };\n");
    try writer.writeAll("    defer fixtures_dir.close();\n");
    try writer.print("    const Case = {s}.TestCase({s}, {s});\n", .{ runner_module, fork_symbol, path_literal });
    try writer.writeAll("    try Case.execute(test_allocator, fixtures_dir);\n");
    try writer.writeAll("}\n\n");
}

fn writeTests(
    allocator: Allocator,
    output_path: []const u8,
    fixtures: [][]const u8,
) !WriteSummary {
    return writeGroupedTests(allocator, output_path, fixtures);
}

fn collectIntoGroups(
    allocator: Allocator,
    fixtures: [][]const u8,
    groups: *std.ArrayList(ForkGroup),
    emitted_count: *usize,
) !void {
    for (fixtures) |rel_path| {
        const route = parseFixtureRoute(rel_path) catch |err| {
            std.debug.print(
                "spectest: skipping unsupported fixture {s}: {s}\n",
                .{ rel_path, @errorName(err) },
            );
            continue;
        };

        var group = blk: {
            for (groups.items) |*existing| {
                if (existing.kind == route.kind and std.mem.eql(u8, existing.fork_name, route.fork_name)) {
                    break :blk existing;
                }
            }

            try groups.append(allocator, ForkGroup{
                .kind = route.kind,
                .fork_name = try allocator.dupe(u8, route.fork_name),
                .fork_symbol = try allocator.dupe(u8, route.fork_symbol),
                .suites = std.ArrayList(SuiteGroup).empty,
            });
            break :blk &groups.items[groups.items.len - 1];
        };

        var suite = blk: {
            for (group.suites.items) |*existing| {
                if (std.mem.eql(u8, existing.suite_name, route.suite)) break :blk existing;
            }

            try group.suites.append(allocator, SuiteGroup{
                .suite_name = try allocator.dupe(u8, route.suite),
                .handlers = std.ArrayList(HandlerGroup).empty,
            });
            break :blk &group.suites.items[group.suites.items.len - 1];
        };

        var handler = blk: {
            for (suite.handlers.items) |*existing| {
                if (std.mem.eql(u8, existing.handler_name, route.handler)) break :blk existing;
            }

            try suite.handlers.append(allocator, HandlerGroup{
                .handler_name = try allocator.dupe(u8, route.handler),
                .entries = std.ArrayList(GroupedEntry).empty,
            });
            break :blk &suite.handlers.items[suite.handlers.items.len - 1];
        };

        try handler.entries.append(allocator, .{ .rel_path = rel_path, .route = route });
        emitted_count.* += 1;
    }

    sortGroups(groups.items);
}

fn sortGroups(groups: []ForkGroup) void {
    std.mem.sort(ForkGroup, groups, {}, struct {
        fn lessThan(_: void, lhs: ForkGroup, rhs: ForkGroup) bool {
            if (lhs.kind != rhs.kind) return @intFromEnum(lhs.kind) < @intFromEnum(rhs.kind);
            return std.mem.lessThan(u8, lhs.fork_name, rhs.fork_name);
        }
    }.lessThan);

    for (groups) |*group| {
        std.mem.sort(SuiteGroup, group.suites.items, {}, struct {
            fn lessThan(_: void, lhs: SuiteGroup, rhs: SuiteGroup) bool {
                return std.mem.lessThan(u8, lhs.suite_name, rhs.suite_name);
            }
        }.lessThan);

        for (group.suites.items) |*suite| {
            std.mem.sort(HandlerGroup, suite.handlers.items, {}, struct {
                fn lessThan(_: void, lhs: HandlerGroup, rhs: HandlerGroup) bool {
                    return std.mem.lessThan(u8, lhs.handler_name, rhs.handler_name);
                }
            }.lessThan);

            for (suite.handlers.items) |*handler| {
                std.mem.sort(GroupedEntry, handler.entries.items, {}, struct {
                    fn lessThan(_: void, lhs: GroupedEntry, rhs: GroupedEntry) bool {
                        return std.mem.lessThan(u8, lhs.rel_path, rhs.rel_path);
                    }
                }.lessThan);
            }
        }
    }
}

fn deinitGroups(allocator: Allocator, groups: *std.ArrayList(ForkGroup)) void {
    for (groups.items) |*group| {
        for (group.suites.items) |*suite| {
            for (suite.handlers.items) |*handler| {
                handler.entries.deinit(allocator);
                allocator.free(handler.handler_name);
            }
            suite.handlers.deinit(allocator);
            allocator.free(suite.suite_name);
        }
        group.suites.deinit(allocator);
        allocator.free(group.fork_name);
        allocator.free(group.fork_symbol);
    }
    groups.deinit(allocator);
}

fn writeGroupedTests(
    allocator: Allocator,
    output_dir: []const u8,
    fixtures: [][]const u8,
) !WriteSummary {
    var path_exists = true;
    std.fs.cwd().access(output_dir, .{}) catch |err| switch (err) {
        error.FileNotFound => path_exists = false,
        else => return err,
    };
    if (path_exists) {
        try std.fs.cwd().deleteTree(output_dir);
    }
    try std.fs.cwd().makePath(output_dir);

    var groups = std.ArrayList(ForkGroup).empty;
    errdefer deinitGroups(allocator, &groups);

    var emitted_count: usize = 0;
    try collectIntoGroups(allocator, fixtures, &groups, &emitted_count);

    if (groups.items.len == 0) {
        try writeEmptyIndex(allocator, output_dir);
        deinitGroups(allocator, &groups);
        return WriteSummary{ .emitted_count = 0, .file_count = 0 };
    }

    const src_dir = std.fs.path.dirname(output_dir) orelse ".";

    var file_count: usize = 0;
    for (groups.items) |*group| {
        for (group.suites.items) |*suite| {
            for (suite.handlers.items) |*handler| {
                try writeHandlerFile(allocator, output_dir, src_dir, group.*, suite.*, handler.*);
                file_count += 1;
            }
        }
    }

    try writeIndexFile(allocator, output_dir, groups.items);

    deinitGroups(allocator, &groups);

    return WriteSummary{ .emitted_count = emitted_count, .file_count = file_count };
}

fn writeHandlerFile(
    allocator: Allocator,
    output_dir: []const u8,
    src_dir: []const u8,
    group: ForkGroup,
    suite: SuiteGroup,
    handler: HandlerGroup,
) !void {
    const kind_segment = group.kind.runnerModule();

    const suite_dir = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/{s}/{s}",
        .{ output_dir, kind_segment, group.fork_name, suite.suite_name },
    );
    defer allocator.free(suite_dir);
    try std.fs.cwd().makePath(suite_dir);

    const handler_dir = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ suite_dir, handler.handler_name },
    );
    defer allocator.free(handler_dir);
    try std.fs.cwd().makePath(handler_dir);

    const file_path = try std.fmt.allocPrint(allocator, "{s}/tests.zig", .{handler_dir});
    defer allocator.free(file_path);

    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    const writer = buffer.writer(allocator);

    const levels_up = computeLevelsUp(handler_dir, src_dir);
    const runner_prefix = try makeRunnerPrefix(allocator, levels_up);
    defer allocator.free(runner_prefix);

    const header_text = try makeHeaderWithPrefix(allocator, runner_prefix, group.kind);
    defer allocator.free(header_text);
    try writer.writeAll(header_text);

    try writer.print("pub const fixture_count: usize = {d};\n\n", .{handler.entries.items.len});

    const runner_module = group.kind.runnerModule();
    for (handler.entries.items) |entry| {
        const label = try std.fmt.allocPrint(
            allocator,
            "{s} {s} {s} {s}",
            .{ entry.route.fork_name, entry.route.suite, entry.route.handler, entry.route.case_name },
        );
        defer allocator.free(label);

        const label_literal = try makeLiteral(allocator, label);
        defer allocator.free(label_literal);

        const path_literal = try makeLiteral(allocator, entry.rel_path);
        defer allocator.free(path_literal);

        try writeTestCase(writer, label_literal, runner_module, group.fork_symbol, path_literal);
    }

    // Write buffer to file
    var file = try std.fs.cwd().createFile(file_path, .{ .truncate = true });
    defer file.close();
    var allocating_write_buf = std.Io.Writer.Allocating.init(allocator);
    defer allocating_write_buf.deinit();
    var file_writer = file.writer(allocating_write_buf.writer.buffer);
    try file_writer.interface.writeAll(buffer.items);
    try file_writer.interface.flush();
}

fn writeIndexFile(
    allocator: Allocator,
    output_dir: []const u8,
    groups: []ForkGroup,
) !void {
    const index_path = try std.fmt.allocPrint(allocator, "{s}/index.zig", .{output_dir});
    defer allocator.free(index_path);

    // Use ArrayList as buffer since File.writer() API changed in Zig 0.15.2
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    const writer = buffer.writer(allocator);

    try writer.writeAll("// This file is generated by pkgs/spectest/src/generator.zig.\n");
    try writer.writeAll("// Do not edit manually.\n\n");

    var total_count: usize = 0;
    inline for (all_kinds) |kind| {
        const runner_name = kind.runnerModule();
        const kind_segment = kind.runnerModule();

        var kind_total: usize = 0;
        try writer.print("pub const {s} = struct {{\n", .{runner_name});

        for (groups) |group| {
            if (group.kind != kind) continue;
            try writer.print("    pub const {s} = struct {{\n", .{group.fork_name});

            var fork_total: usize = 0;
            for (group.suites.items) |suite| {
                try writer.print("        pub const {s} = struct {{\n", .{suite.suite_name});

                var suite_total: usize = 0;
                for (suite.handlers.items) |handler| {
                    const import_path = try std.fmt.allocPrint(
                        allocator,
                        "{s}/{s}/{s}/{s}/tests.zig",
                        .{ kind_segment, group.fork_name, suite.suite_name, handler.handler_name },
                    );
                    defer allocator.free(import_path);
                    try writer.print(
                        "            pub const {s} = @import(\"{s}\");\n",
                        .{ handler.handler_name, import_path },
                    );
                    suite_total += handler.entries.items.len;
                }

                try writer.print("            pub const fixture_count: usize = {d};\n", .{suite_total});
                try writer.writeAll("        };\n\n");

                fork_total += suite_total;
            }

            try writer.print("        pub const fixture_count: usize = {d};\n", .{fork_total});
            try writer.writeAll("    };\n\n");

            kind_total += fork_total;
        }

        try writer.print("    pub const fixture_count: usize = {d};\n", .{kind_total});
        try writer.writeAll("};\n\n");

        total_count += kind_total;
    }

    try writer.print("pub const fixture_count: usize = {d};\n", .{total_count});

    // Write buffer to file
    var file = try std.fs.cwd().createFile(index_path, .{ .truncate = true });
    defer file.close();
    var allocating_write_buf = std.Io.Writer.Allocating.init(allocator);
    defer allocating_write_buf.deinit();
    var file_writer = file.writer(allocating_write_buf.writer.buffer);
    try file_writer.interface.writeAll(buffer.items);
    try file_writer.interface.flush();
}

fn writeEmptyIndex(
    allocator: Allocator,
    output_dir: []const u8,
) !void {
    const index_path = try std.fmt.allocPrint(allocator, "{s}/index.zig", .{output_dir});
    defer allocator.free(index_path);

    // Use ArrayList as buffer since File.writer() API changed in Zig 0.15.2
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    const writer = buffer.writer(allocator);
    try writer.writeAll("// This file is generated by pkgs/spectest/src/generator.zig.\n");
    try writer.writeAll("// Do not edit manually.\n\n");
    try writer.writeAll("pub const state_transition = struct {\n");
    try writer.writeAll("    pub const fixture_count: usize = 0;\n");
    try writer.writeAll("};\n\n");
    try writer.writeAll("pub const fork_choice = struct {\n");
    try writer.writeAll("    pub const fixture_count: usize = 0;\n");
    try writer.writeAll("};\n\n");
    try writer.writeAll("pub const fixture_count: usize = 0;\n");

    // Write buffer to file
    var file = try std.fs.cwd().createFile(index_path, .{ .truncate = true });
    defer file.close();
    var allocating_write_buf = std.Io.Writer.Allocating.init(allocator);
    defer allocating_write_buf.deinit();
    var file_writer = file.writer(allocating_write_buf.writer.buffer);
    try file_writer.interface.writeAll(buffer.items);
    try file_writer.interface.flush();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    var options = parseArgs(allocator, argv) catch |err| switch (err) {
        error.DisplayHelp, error.InvalidArgument => return,
        else => return err,
    };
    defer options.deinit();

    const fixtures = blk: {
        ensureVectorsRoot(&options) catch |err| switch (err) {
            error.FixtureRootNotFound => {
                std.debug.print(
                    "spectest: fixture root not found at {s}; generating stub file\n",
                    .{options.vectors_root},
                );
                break :blk try allocator.alloc([]const u8, 0);
            },
            else => return err,
        };

        break :blk collectFixtures(allocator, options.vectors_root) catch |err| switch (err) {
            error.FixtureRootNotFound => blk_inner: {
                std.debug.print(
                    "spectest: fixture root not found at {s}; generating stub file\n",
                    .{options.vectors_root},
                );
                break :blk_inner try allocator.alloc([]const u8, 0);
            },
            else => return err,
        };
    };
    defer {
        for (fixtures) |item| allocator.free(item);
        allocator.free(fixtures);
    }

    if (options.dry_run) {
        std.debug.print("spectest: discovered {d} fixtures under {s}\n", .{ fixtures.len, options.vectors_root });
        for (fixtures) |item| {
            std.debug.print("  {s}\n", .{item});
        }
        return;
    }

    const summary = try writeTests(
        allocator,
        options.output_path,
        fixtures,
    );
    std.debug.print(
        "spectest: wrote {d} tests across {d} handler files under {s}\n",
        .{ summary.emitted_count, summary.file_count, options.output_path },
    );
}
