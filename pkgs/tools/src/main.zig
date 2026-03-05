const std = @import("std");
const enr = @import("enr");
const build_options = @import("build_options");
const simargs = @import("simargs");
const xmss = @import("@zeam/xmss");

pub const max_enr_txt_size = enr.max_enr_txt_size;

const ToolsArgs = struct {
    help: bool = false,
    version: bool = false,

    __commands__: union(enum) {
        enrgen: ENRGenCmd,
        keygen: KeyGenCmd,

        pub const __messages__ = .{
            .enrgen = "Generate a new ENR (Ethereum Node Record)",
            .keygen = "Generate pre-computed XMSS test validator keys",
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

    const KeyGenCmd = struct {
        @"num-validators": usize = 32,
        @"num-active-epochs": usize = 1000,
        @"output-dir": []const u8 = "test-keys",
        help: bool = false,

        pub const __shorts__ = .{
            .@"num-validators" = .n,
            .@"num-active-epochs" = .e,
            .@"output-dir" = .o,
            .help = .h,
        };

        pub const __messages__ = .{
            .@"num-validators" = "Number of validator key pairs to generate (default: 32)",
            .@"num-active-epochs" = "Number of active epochs for each key (default: 1000)",
            .@"output-dir" = "Output directory for generated keys (default: test-keys)",
            .help = "Show help information for the keygen command",
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
        .keygen => |cmd| {
            handleKeyGen(allocator, cmd) catch |err| {
                std.debug.print("Error generating keys: {}\n", .{err});
                std.process.exit(1);
            };
        },
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

fn handleKeyGen(allocator: std.mem.Allocator, cmd: ToolsArgs.KeyGenCmd) !void {
    const num_validators = cmd.@"num-validators";
    const num_active_epochs = cmd.@"num-active-epochs";
    const output_dir = cmd.@"output-dir";

    std.debug.print("Generating {d} validator keys with {d} active epochs...\n", .{ num_validators, num_active_epochs });
    std.debug.print("Output directory: {s}\n", .{output_dir});

    // Create output directories
    const hash_sig_dir = try std.fmt.allocPrint(allocator, "{s}/hash-sig-keys", .{output_dir});
    defer allocator.free(hash_sig_dir);

    std.fs.cwd().makePath(hash_sig_dir) catch |err| {
        std.debug.print("Error creating directory {s}: {}\n", .{ hash_sig_dir, err });
        return err;
    };

    // Allocate buffers for serialization
    // Private keys can be very large (~5-10MB for XMSS)
    const sk_buffer = try allocator.alloc(u8, 1024 * 1024 * 20); // 20MB
    defer allocator.free(sk_buffer);
    var pk_buffer: [256]u8 = undefined;

    // Open manifest file
    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/validator-keys-manifest.yaml", .{output_dir});
    defer allocator.free(manifest_path);
    const manifest_file = try std.fs.cwd().createFile(manifest_path, .{});
    defer manifest_file.close();

    var manifest_buf: [4096]u8 = undefined;
    var manifest_writer = manifest_file.writer(&manifest_buf);

    // Write manifest header
    try manifest_writer.interface.print(
        \\key_scheme: SIGTopLevelTargetSumLifetime32Dim64Base8
        \\hash_function: Poseidon2
        \\encoding: TargetSum
        \\lifetime: {d}
        \\num_active_epochs: {d}
        \\num_validators: {d}
        \\validators:
        \\
    , .{ num_active_epochs, num_active_epochs, num_validators });

    for (0..num_validators) |i| {
        std.debug.print("  Generating validator {d}/{d}...\n", .{ i + 1, num_validators });

        // Generate keypair with deterministic seed
        const seed = try std.fmt.allocPrint(allocator, "test_validator_{d}", .{i});
        defer allocator.free(seed);

        var keypair = try xmss.KeyPair.generate(allocator, seed, 0, num_active_epochs);
        defer keypair.deinit();

        // Serialize public key
        const pk_len = try keypair.pubkeyToBytes(&pk_buffer);

        // Serialize private key
        const sk_len = try keypair.privkeyToBytes(sk_buffer);

        std.debug.print("    PK size: {d} bytes, SK size: {d} bytes\n", .{ pk_len, sk_len });

        // Write private key file
        const sk_filename = try std.fmt.allocPrint(allocator, "validator_{d}_sk.ssz", .{i});
        defer allocator.free(sk_filename);
        const sk_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ hash_sig_dir, sk_filename });
        defer allocator.free(sk_path);

        const sk_file = try std.fs.cwd().createFile(sk_path, .{});
        defer sk_file.close();
        var sk_write_buf: [65536]u8 = undefined;
        var sk_writer = sk_file.writer(&sk_write_buf);
        try sk_writer.interface.writeAll(sk_buffer[0..sk_len]);
        try sk_writer.interface.flush();

        // Write public key file
        const pk_filename = try std.fmt.allocPrint(allocator, "validator_{d}_pk.ssz", .{i});
        defer allocator.free(pk_filename);
        const pk_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ hash_sig_dir, pk_filename });
        defer allocator.free(pk_path);

        const pk_file = try std.fs.cwd().createFile(pk_path, .{});
        defer pk_file.close();
        var pk_write_buf: [4096]u8 = undefined;
        var pk_writer = pk_file.writer(&pk_write_buf);
        try pk_writer.interface.writeAll(pk_buffer[0..pk_len]);
        try pk_writer.interface.flush();

        // Write manifest entry with pubkey as hex
        // Format pubkey bytes as hex string
        var hex_buf: [512]u8 = undefined;
        const hex_len = pk_len * 2;
        for (pk_buffer[0..pk_len], 0..) |byte, j| {
            const high = byte >> 4;
            const low = byte & 0x0f;
            hex_buf[j * 2] = if (high < 10) '0' + high else 'a' + high - 10;
            hex_buf[j * 2 + 1] = if (low < 10) '0' + low else 'a' + low - 10;
        }

        try manifest_writer.interface.print(
            \\- index: {d}
            \\  pubkey_hex: "0x{s}"
            \\  privkey_file: {s}
            \\
        , .{ i, hex_buf[0..hex_len], sk_filename });
    }

    try manifest_writer.interface.flush();

    std.debug.print("\nDone! Generated {d} keys in {s}/\n", .{ num_validators, output_dir });
    std.debug.print("Manifest written to {s}\n", .{manifest_path});
}

fn handleENRGen(cmd: ToolsArgs.ENRGenCmd) !void {
    if (cmd.sk.len == 0) {
        return error.EmptySecretKey;
    }

    if (cmd.ip.len == 0) {
        return error.EmptyIPAddress;
    }

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var buffer: std.ArrayList(u8) = .empty;
    try genENR(cmd.sk, cmd.ip, cmd.quic, buffer.writer(alloc));

    if (cmd.out) |output_path| {
        // Write the result to the file
        const file = try std.fs.cwd().createFile(output_path, .{});
        defer file.close();
        var write_buf: [max_enr_txt_size]u8 = undefined;
        var file_writer = file.writer(&write_buf);
        try file_writer.interface.writeAll(buffer.items);
        try file_writer.interface.flush();

        std.debug.print("ENR written to: {s}\n", .{output_path});
    } else {
        // Write the result to stdout
        const stdout = std.fs.File.stdout();
        var stdout_write_buf: [max_enr_txt_size]u8 = undefined;
        var stdout_writer = stdout.writer(&stdout_write_buf);
        try stdout_writer.interface.writeAll(buffer.items);
        try stdout_writer.interface.flush();
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
    const allocator = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    try genENR("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", "192.0.2.1", 1234, buffer.writer(allocator));

    try std.testing.expectEqualStrings("enr:-IW4QP3E2K97wLIvYbu2upNn5CfjWdD4kmW6YjxNcdroKIA_V81rQhAtp_JG711GtlHXStpGT03JZzM1I3VoAj9S5Z-AgmlkgnY0gmlwhMAAAgGEcXVpY4IE0olzZWNwMjU2azGhA8pjTK4NSay0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4", buffer.items);
}

test "generate ENR with 0x prefix" {
    const allocator = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    try genENR("0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", "127.0.0.1", 30303, buffer.writer(allocator));

    try std.testing.expectEqualStrings("enr:-IW4QI9SLVH8scoBp80eUJdBENXALDXyf4psnqjs9be2rVYgcLY-R9FUPU0Ykg1o44fYBacr3V9OyfyXuggsBIDgbSOAgmlkgnY0gmlwhH8AAAGEcXVpY4J2X4lzZWNwMjU2azGhA8pjTK4NSay0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4", buffer.items);
}

test "invalid secret key length" {
    const allocator = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    const result = genENR("invalid", "127.0.0.1", 30303, buffer.writer(allocator));
    try std.testing.expectError(error.InvalidSecretKeyLength, result);
}

test "invalid IP address" {
    const allocator = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    const result = genENR("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", "invalid.ip", 30303, buffer.writer(allocator));
    try std.testing.expectError(error.InvalidIPAddress, result);
}
