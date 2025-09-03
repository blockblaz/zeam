const std = @import("std");
const enr = @import("enr");
const build_options = @import("build_options");
const simargs = @import("simargs");

const ToolsArgs = struct {
    help: bool = false,
    version: bool = false,

    __commands__: union(enum) {
        enrgen: ENRGenCmd,

        pub const __messages__ = .{
            .enrgen = "Generate a new ENR (Ethereum Node Record)",
        };
    },

    pub const __shorts__ = .{
        .help = .h,
        .version = .v,
    };

    pub const __messages__ = .{
        .help = "Show help information",
        .version = "Show version information",
    };

    const ENRGenCmd = struct {
        sk: []const u8,
        ip: []const u8,
        quic: u16,
        out: ?[]const u8 = null,
        help: bool = false,

        pub const __shorts__ = .{
            .sk = .s,
            .ip = .i,
            .quic = .q,
            .out = .o,
            .help = .h,
        };

        pub const __messages__ = .{
            .sk = "Secret key (hex string with or without 0x prefix)",
            .ip = "IPv4 address for the ENR",
            .quic = "QUIC port for discovery",
            .out = "Output file path (prints to stdout if not specified)",
            .help = "Show help information for the enrgen command",
        };
    };
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const app_description = "Zeam Tools - Utilities for Beam Chain development";
    const app_version = build_options.version;

    const opts = simargs.parse(allocator, ToolsArgs, app_description, app_version) catch |err| switch (err) {
        error.MissingSubCommand => {
            std.debug.print("Error: Missing subcommand. Use --help for usage information.\n", .{});
            std.process.exit(1);
        },
        error.MissingRequiredOption => {
            std.debug.print("Error: Missing required arguments. Use --help for usage information.\n", .{});
            std.process.exit(1);
        },
        error.MissingOptionValue => {
            std.debug.print("Error: Missing value for option. Use --help for usage information.\n", .{});
            std.process.exit(1);
        },
        error.InvalidEnumValue => {
            std.debug.print("Error: Invalid option value. Use --help for usage information.\n", .{});
            std.process.exit(1);
        },
        else => {
            std.debug.print("Error parsing arguments: {}. Use --help for usage information.\n", .{err});
            std.process.exit(1);
        },
    };
    defer opts.deinit();
    defer enr.deinitGlobalSecp256k1Ctx();

    switch (opts.args.__commands__) {
        .enrgen => |cmd| {
            handleENRGen(cmd) catch |err| switch (err) {
                error.EmptySecretKey => {
                    std.debug.print("Error: Secret key cannot be empty\n", .{});
                    std.process.exit(1);
                },
                error.EmptyIPAddress => {
                    std.debug.print("Error: IP address cannot be empty\n", .{});
                    std.process.exit(1);
                },
                error.InvalidSecretKeyLength => {
                    std.debug.print("Error: Secret key must be 32 bytes (64 hex characters)\n", .{});
                    std.process.exit(1);
                },
                error.InvalidIPAddress => {
                    std.debug.print("Error: Invalid IP address format\n", .{});
                    std.process.exit(1);
                },
                else => {
                    std.debug.print("Error: {}\n", .{err});
                    std.process.exit(1);
                },
            };
        },
    }
}

fn handleENRGen(cmd: ToolsArgs.ENRGenCmd) !void {
    if (cmd.sk.len == 0) {
        return error.EmptySecretKey;
    }

    if (cmd.ip.len == 0) {
        return error.EmptyIPAddress;
    }

    if (cmd.out) |output_path| {
        const file = try std.fs.cwd().createFile(output_path, .{});
        defer file.close();

        const writer = file.writer();
        try genENR(cmd.sk, cmd.ip, cmd.quic, writer);

        std.debug.print("ENR written to: {s}\n", .{output_path});
    } else {
        const stdout = std.io.getStdOut().writer();
        try genENR(cmd.sk, cmd.ip, cmd.quic, stdout);
    }
}

fn genENR(secret_key: []const u8, ip: []const u8, quic: u16, out_writer: anytype) !void {
    var secret_key_bytes: [32]u8 = undefined;
    const secret_key_str = if (std.mem.startsWith(u8, secret_key, "0x"))
        secret_key[2..]
    else
        secret_key;

    if (secret_key_str.len != 64) {
        return error.InvalidSecretKeyLength;
    }

    _ = std.fmt.hexToBytes(&secret_key_bytes, secret_key_str) catch {
        return error.InvalidSecretKeyFormat;
    };

    var signable_enr = enr.SignableENR.fromSecretKeyString(secret_key_str) catch {
        return error.ENRCreationFailed;
    };

    const ip_addr = std.net.Ip4Address.parse(ip, 0) catch {
        return error.InvalidIPAddress;
    };
    const ip_addr_bytes = std.mem.asBytes(&ip_addr.sa.addr);
    signable_enr.set("ip", ip_addr_bytes) catch {
        return error.ENRSetIPFailed;
    };

    var quic_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &quic_bytes, quic, .big);
    signable_enr.set("quic", &quic_bytes) catch {
        return error.ENRSetQUICFailed;
    };

    try enr.writeSignableENR(out_writer, &signable_enr);
}

test "generate ENR to buffer" {
    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try genENR("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", "192.0.2.1", 1234, writer);

    const result = fbs.getWritten();

    try std.testing.expectEqualStrings("enr:-IW4QP3E2K97wLIvYbu2upNn5CfjWdD4kmW6YjxNcdroKIA_V81rQhAtp_JG711GtlHXStpGT03JZzM1I3VoAj9S5Z-AgmlkgnY0gmlwhMAAAgGEcXVpY4IE0olzZWNwMjU2azGhA8pjTK4NSay0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4", result);
}

test "generate ENR with 0x prefix" {
    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try genENR("0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", "127.0.0.1", 30303, writer);

    const result = fbs.getWritten();
    try std.testing.expectEqualStrings("enr:-IW4QI9SLVH8scoBp80eUJdBENXALDXyf4psnqjs9be2rVYgcLY-R9FUPU0Ykg1o44fYBacr3V9OyfyXuggsBIDgbSOAgmlkgnY0gmlwhH8AAAGEcXVpY4J2X4lzZWNwMjU2azGhA8pjTK4NSay0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4", result);
}

test "invalid secret key length" {
    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    const result = genENR("invalid", "127.0.0.1", 30303, writer);
    try std.testing.expectError(error.InvalidSecretKeyLength, result);
}

test "invalid IP address" {
    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    const result = genENR("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", "invalid.ip", 30303, writer);
    try std.testing.expectError(error.InvalidIPAddress, result);
}
