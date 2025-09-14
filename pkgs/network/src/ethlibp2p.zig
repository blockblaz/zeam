const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const ssz = @import("ssz");
const types = @import("@zeam/types");
const xev = @import("xev");
const Multiaddr = @import("multiformats").multiaddr.Multiaddr;
const zeam_utils = @import("@zeam/utils");

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

/// Writes failed deserialization bytes to disk for debugging purposes
/// Returns the filename if the file was successfully created, null otherwise
/// If timestamp is null, generates a new timestamp automatically
fn writeFailedBytes(message_bytes: []const u8, message_type: []const u8, allocator: Allocator, timestamp: ?i64, logger: *const zeam_utils.ZeamLogger) ?[]const u8 {
    // Create dumps directory if it doesn't exist
    std.fs.cwd().makeDir("deserialization_dumps") catch |e| switch (e) {
        error.PathAlreadyExists => {}, // Directory already exists, continue
        else => {
            logger.err("Failed to create deserialization dumps directory: {any}", .{e});
            return null;
        },
    };

    // Generate timestamp-based filename
    const actual_timestamp = timestamp orelse std.time.timestamp();
    const filename = std.fmt.allocPrint(allocator, "deserialization_dumps/failed_{s}_{d}.bin", .{ message_type, actual_timestamp }) catch |e| {
        logger.err("Failed to allocate filename for {s} deserialization dump: {any}", .{ message_type, e });
        return null;
    };
    defer allocator.free(filename);

    // Write bytes to file
    const file = std.fs.cwd().createFile(filename, .{ .truncate = true }) catch |e| {
        logger.err("Failed to create file {s} for {s} deserialization dump: {any}", .{ filename, message_type, e });
        return null;
    };
    defer file.close();

    file.writeAll(message_bytes) catch |e| {
        logger.err("Failed to write {d} bytes to file {s} for {s} deserialization dump: {any}", .{ message_bytes.len, filename, message_type, e });
        return null;
    };

    logger.warn("SSZ deserialization failed for {s} message - written {d} bytes to debug file: {s}", .{ message_type, message_bytes.len, filename });
    return filename;
}

export fn handleMsgFromRustBridge(zigHandler: *EthLibp2p, topic_str: [*:0]const u8, message_ptr: [*]const u8, message_len: usize) void {
    const topic = interface.GossipTopic.parseTopic(topic_str) orelse {
        zigHandler.logger.err("Ignoring Invalid topic_id={d} sent in handleMsgFromRustBridge", .{std.mem.span(topic_str)});
        return;
    };

    const message_bytes: []const u8 = message_ptr[0..message_len];
    const message: interface.GossipMessage = switch (topic) {
        .block => blockmessage: {
            var message_data: types.SignedBeamBlock = undefined;
            ssz.deserialize(types.SignedBeamBlock, message_bytes, &message_data, zigHandler.allocator) catch |e| {
                zigHandler.logger.err("Error in deserializing the signed block message: {any}", .{e});
                if (writeFailedBytes(message_bytes, "block", zigHandler.allocator, null, zigHandler.logger)) |filename| {
                    zigHandler.logger.err("Block deserialization failed - debug file created: {s}", .{filename});
                } else {
                    zigHandler.logger.err("Block deserialization failed - could not create debug file", .{});
                }
                return;
            };

            break :blockmessage .{ .block = message_data };
        },
        .vote => votemessage: {
            var message_data: types.SignedVote = undefined;
            ssz.deserialize(types.SignedVote, message_bytes, &message_data, zigHandler.allocator) catch |e| {
                zigHandler.logger.err("Error in deserializing the signed vote message: {any}", .{e});
                if (writeFailedBytes(message_bytes, "vote", zigHandler.allocator, null, zigHandler.logger)) |filename| {
                    zigHandler.logger.err("Vote deserialization failed - debug file created: {s}", .{filename});
                } else {
                    zigHandler.logger.err("Vote deserialization failed - could not create debug file", .{});
                }
                return;
            };
            break :votemessage .{ .vote = message_data };
        },
    };

    zigHandler.logger.debug("\network-{d}:: !!!handleMsgFromRustBridge topic={s}:: message={any} from bytes={any} \n", .{ zigHandler.params.networkId, std.mem.span(topic_str), message, message_bytes });

    // TODO: figure out why scheduling on the loop is not working
    zigHandler.gossipHandler.onGossip(&message, false) catch |e| {
        zigHandler.logger.err("onGossip handling of message failed with error e={any}", .{e});
    };
}

export fn releaseAddresses(zigHandler: *EthLibp2p, listenAddresses: [*:0]const u8, connectAddresses: [*:0]const u8) void {
    const listen_slice = std.mem.span(listenAddresses);
    zigHandler.allocator.free(listen_slice);

    const connect_slice = std.mem.span(connectAddresses);
    // because connectAddresses can be empty string "" which not allocate memory in the heap
    if (connect_slice.len > 0) {
        zigHandler.allocator.free(connect_slice);
    }
}

// TODO: change listen port and connect port both to list of multiaddrs
pub extern fn create_and_run_network(networkId: u32, a: *EthLibp2p, listenAddresses: [*:0]const u8, connectAddresses: [*:0]const u8) void;
pub extern fn publish_msg_to_rust_bridge(networkId: u32, topic_str: [*:0]const u8, message_ptr: [*]const u8, message_len: usize) void;

pub const EthLibp2pParams = struct {
    networkId: u32,
    listen_addresses: []const Multiaddr,
    connect_peers: ?[]const Multiaddr,
};

pub const EthLibp2p = struct {
    allocator: Allocator,
    gossipHandler: interface.GenericGossipHandler,
    params: EthLibp2pParams,
    rustBridgeThread: ?Thread = null,
    logger: *const zeam_utils.ZeamLogger,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        loop: *xev.Loop,
        params: EthLibp2pParams,
        logger: *const zeam_utils.ZeamLogger,
    ) !Self {
        return Self{ .allocator = allocator, .params = params, .gossipHandler = try interface.GenericGossipHandler.init(allocator, loop, params.networkId, logger), .logger = logger };
    }

    pub fn run(self: *Self) !void {
        const listen_addresses_str = try multiaddrsToString(self.allocator, self.params.listen_addresses);
        const connect_peers_str = if (self.params.connect_peers) |peers|
            try multiaddrsToString(self.allocator, peers)
        else
            "";
        self.rustBridgeThread = try Thread.spawn(.{}, create_and_run_network, .{ self.params.networkId, self, listen_addresses_str.ptr, connect_peers_str.ptr });
    }

    pub fn publish(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        // publish
        const topic = data.getTopic();
        const topic_str: [*:0]const u8 = @ptrCast(@tagName(topic));

        // TODO: deinit the message later ob once done
        const message = switch (topic) {
            .block => blockbytes: {
                var serialized = std.ArrayList(u8).init(self.allocator);
                try ssz.serialize(types.SignedBeamBlock, data.block, &serialized);

                break :blockbytes serialized.items;
            },
            .vote => votebytes: {
                var serialized = std.ArrayList(u8).init(self.allocator);
                try ssz.serialize(types.SignedVote, data.vote, &serialized);

                break :votebytes serialized.items;
            },
        };
        self.gossipHandler.logger.debug("network-{d}:: calling publish_msg_to_rust_bridge with message={any} for data={any}", .{ self.params.networkId, message, data });
        publish_msg_to_rust_bridge(self.params.networkId, topic_str, message.ptr, message.len);
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.subscribe(topics, handler);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.onGossip(data, false);
    }

    pub fn reqResp(ptr: *anyopaque, obj: *interface.ReqRespRequest) anyerror!void {
        _ = ptr;
        _ = obj;
    }

    pub fn onReq(ptr: *anyopaque, data: *interface.ReqRespRequest) anyerror!void {
        _ = ptr;
        _ = data;
    }

    pub fn getNetworkInterface(self: *Self) NetworkInterface {
        return .{ .gossip = .{
            .ptr = self,
            .publishFn = publish,
            .subscribeFn = subscribe,
            .onGossipFn = onGossip,
        }, .reqresp = .{
            .ptr = self,
            .reqRespFn = reqResp,
            .onReqFn = onReq,
        } };
    }

    fn multiaddrsToString(allocator: Allocator, addrs: []const Multiaddr) ![:0]u8 {
        if (addrs.len == 0) {
            return try allocator.dupeZ(u8, "");
        }

        var addr_strings = std.ArrayList([]const u8).init(allocator);
        defer {
            for (addr_strings.items) |addr_str| {
                allocator.free(addr_str);
            }
            addr_strings.deinit();
        }

        for (addrs) |addr| {
            const addr_str = try addr.toString(allocator);
            try addr_strings.append(addr_str);
        }

        const joined = try std.mem.join(allocator, ",", addr_strings.items);
        defer allocator.free(joined);

        const result = try allocator.dupeZ(u8, joined);

        return result;
    }
};

test "writeFailedBytes creates file with correct content" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a test logger
    var test_logger = zeam_utils.getTestLogger();

    // Ensure directory exists before test (CI-safe)
    std.fs.cwd().makeDir("deserialization_dumps") catch {};

    // Use a predictable timestamp for deterministic filename
    const test_timestamp: i64 = 1234567890;

    // Test case 1: Valid data that should succeed
    const valid_bytes = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    const result1 = writeFailedBytes(&valid_bytes, "test", allocator, test_timestamp, &test_logger);
    testing.expect(result1 != null) catch {
        std.debug.print("writeFailedBytes should return filename for valid data\n", .{});
    };

    // Now verify the file was created and contains correct content
    const expected_filename = "deserialization_dumps/failed_test_1234567890.bin";
    const file = std.fs.cwd().openFile(expected_filename, .{}) catch |e| {
        std.debug.print("Failed to open created file: {any}\n", .{e});
        testing.expect(false) catch {};
        return;
    };
    defer file.close();

    // Read all file contents
    const file_contents = file.readToEndAlloc(allocator, 1024) catch |e| {
        std.debug.print("Failed to read file contents: {any}\n", .{e});
        testing.expect(false) catch {};
        return;
    };
    defer allocator.free(file_contents);

    // Verify the file contains exactly the bytes we provided
    testing.expectEqualSlices(u8, &valid_bytes, file_contents) catch {
        std.debug.print("File contents don't match expected bytes. Expected: {any}, Got: {any}\n", .{ &valid_bytes, file_contents });
    };

    // Test case 2: Empty data that should still succeed
    const empty_bytes = [_]u8{};
    const result2 = writeFailedBytes(&empty_bytes, "empty", allocator, test_timestamp, &test_logger);
    testing.expect(result2 != null) catch {
        std.debug.print("writeFailedBytes should return filename for empty data\n", .{});
    };

    // Verify empty file was created
    const empty_filename = "deserialization_dumps/failed_empty_1234567890.bin";
    const empty_file = std.fs.cwd().openFile(empty_filename, .{}) catch |e| {
        std.debug.print("Failed to open empty file: {any}\n", .{e});
        testing.expect(false) catch {};
        return;
    };
    defer empty_file.close();

    const empty_contents = empty_file.readToEndAlloc(allocator, 1024) catch |e| {
        std.debug.print("Failed to read empty file contents: {any}\n", .{e});
        testing.expect(false) catch {};
        return;
    };
    defer allocator.free(empty_contents);

    testing.expectEqualSlices(u8, &empty_bytes, empty_contents) catch {
        std.debug.print("Empty file contents don't match expected bytes. Expected: {any}, Got: {any}\n", .{ &empty_bytes, empty_contents });
    };

    // Cleanup after we're done with the directory
    std.fs.cwd().deleteTree("deserialization_dumps") catch {};
}
