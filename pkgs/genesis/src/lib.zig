const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const types = @import("@zeam/types");
const enr = @import("enr");
const sftFactory = @import("@zeam/state-transition");
const ssz = @import("ssz");

pub const GenesisGenerator = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }

    pub fn generate(
        self: *Self,
        config_path: []const u8,
        validators_path: []const u8,
        output_dir: []const u8,
    ) !void {
        // 0. Create output directory if it doesn't exist
        std.fs.cwd().makeDir(output_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        // 1. Parse configuration files
        const config = try self.parseConfig(config_path);
        const validators_config = try self.parseValidatorsConfig(validators_path);

        // 2. Generate ENRs for validators that need them
        const enrs = try self.generateENRs(validators_config);

        // 3. Calculate validator indices using shuffle strategy
        const validator_indices = try self.calculateValidatorIndices(validators_config);

        // 4. Update config with total validator count
        var updated_config = config;
        var total_validators: u32 = 0;
        for (validators_config.validators) |validator| {
            total_validators += validator.count;
        }
        updated_config.VALIDATOR_COUNT = total_validators;

        // 5. Generate output files
        try self.writeConfigOutput(output_dir, updated_config);
        try self.writeNodesOutput(output_dir, enrs);
        try self.writeValidatorsOutput(output_dir, validator_indices);

        // 6. Generate genesis state and block
        try self.generateGenesisState(output_dir, updated_config);
    }

    fn parseConfig(self: *Self, config_path: []const u8) !types.GenesisConfig {
        const file = try std.fs.cwd().openFile(config_path, .{});
        defer file.close();

        const file_size = try file.getEndPos();
        const contents = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(contents);

        _ = try file.readAll(contents);

        // Parse YAML format: GENESIS_TIME: 1704085200, VALIDATOR_COUNT: 0
        var lines = std.mem.splitSequence(u8, contents, "\n");
        var config = types.GenesisConfig{
            .GENESIS_TIME = 0,
            .VALIDATOR_COUNT = 0,
        };

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue; // Skip empty lines and comments

            if (std.mem.startsWith(u8, trimmed, "GENESIS_TIME:")) {
                const value_str = std.mem.trim(u8, trimmed["GENESIS_TIME:".len..], " \t");
                config.GENESIS_TIME = std.fmt.parseInt(u64, value_str, 10) catch 0;
            } else if (std.mem.startsWith(u8, trimmed, "VALIDATOR_COUNT:")) {
                const value_str = std.mem.trim(u8, trimmed["VALIDATOR_COUNT:".len..], " \t");
                config.VALIDATOR_COUNT = std.fmt.parseInt(u32, value_str, 10) catch 0;
            }
        }

        return config;
    }

    fn parseValidatorsConfig(self: *Self, validators_path: []const u8) !types.ValidatorConfigFile {
        const file = try std.fs.cwd().openFile(validators_path, .{});
        defer file.close();

        const file_size = try file.getEndPos();
        const contents = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(contents);

        _ = try file.readAll(contents);

        // Parse YAML format manually
        var lines = std.mem.splitSequence(u8, contents, "\n");
        var shuffle: ?[]const u8 = null;
        var validators = std.ArrayList(types.ValidatorConfig).init(self.allocator);
        var current_validator: ?types.ValidatorConfig = null;
        var in_enr_fields = false;
        var enr_fields = types.ENRFields{};
        var custom_fields = std.ArrayList(types.CustomField).init(self.allocator);

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue; // Skip empty lines and comments

            // Parse shuffle
            if (std.mem.startsWith(u8, trimmed, "shuffle:")) {
                shuffle = try self.allocator.dupe(u8, std.mem.trim(u8, trimmed["shuffle:".len..], " \t"));
            }
            // Parse validators list
            else if (std.mem.startsWith(u8, trimmed, "validators:")) {
                // Start of validators list
            }
            // Parse validator entry
            else if (std.mem.startsWith(u8, trimmed, "- name:")) {
                // Save previous validator if exists
                if (current_validator) |*validator| {
                    if (in_enr_fields) {
                        validator.enrFields = enr_fields;
                        in_enr_fields = false;
                    }
                    try validators.append(validator.*);
                }

                // Start new validator
                const name_start = trimmed["- name: \"".len..];
                const name_end = std.mem.indexOf(u8, name_start, "\"") orelse name_start.len;
                current_validator = types.ValidatorConfig{
                    .name = try self.allocator.dupe(u8, name_start[0..name_end]),
                    .enr = null,
                    .privkey = null,
                    .enrFields = null,
                    .count = 0,
                };
            }
            // Parse validator fields
            else if (current_validator) |*validator| {
                if (std.mem.startsWith(u8, trimmed, "enr:")) {
                    const enr_start = trimmed["enr: \"".len..];
                    const enr_end = std.mem.indexOf(u8, enr_start, "\"") orelse enr_start.len;
                    validator.enr = try self.allocator.dupe(u8, enr_start[0..enr_end]);
                } else if (std.mem.startsWith(u8, trimmed, "privkey:")) {
                    const privkey_start = trimmed["privkey: \"".len..];
                    const privkey_end = std.mem.indexOf(u8, privkey_start, "\"") orelse privkey_start.len;
                    validator.privkey = try self.allocator.dupe(u8, privkey_start[0..privkey_end]);
                } else if (std.mem.startsWith(u8, trimmed, "count:")) {
                    const count_str = std.mem.trim(u8, trimmed["count:".len..], " \t");
                    validator.count = std.fmt.parseInt(u32, count_str, 10) catch 0;
                } else if (std.mem.startsWith(u8, trimmed, "enrFields:")) {
                    in_enr_fields = true;
                    enr_fields = types.ENRFields{};
                    custom_fields.clearRetainingCapacity();
                } else if (in_enr_fields) {
                    // Parse ENR fields
                    if (std.mem.startsWith(u8, trimmed, "ip:")) {
                        const ip_start = trimmed["ip: \"".len..];
                        const ip_end = std.mem.indexOf(u8, ip_start, "\"") orelse ip_start.len;
                        enr_fields.ip = try self.allocator.dupe(u8, ip_start[0..ip_end]);
                    } else if (std.mem.startsWith(u8, trimmed, "ip6:")) {
                        const ip6_start = trimmed["ip6: \"".len..];
                        const ip6_end = std.mem.indexOf(u8, ip6_start, "\"") orelse ip6_start.len;
                        enr_fields.ip6 = try self.allocator.dupe(u8, ip6_start[0..ip6_end]);
                    } else if (std.mem.startsWith(u8, trimmed, "tcp:")) {
                        const tcp_str = std.mem.trim(u8, trimmed["tcp:".len..], " \t");
                        enr_fields.tcp = std.fmt.parseInt(u16, tcp_str, 10) catch null;
                    } else if (std.mem.startsWith(u8, trimmed, "udp:")) {
                        const udp_str = std.mem.trim(u8, trimmed["udp:".len..], " \t");
                        enr_fields.udp = std.fmt.parseInt(u16, udp_str, 10) catch null;
                    } else if (std.mem.startsWith(u8, trimmed, "quic:")) {
                        const quic_str = std.mem.trim(u8, trimmed["quic:".len..], " \t");
                        enr_fields.quic = std.fmt.parseInt(u16, quic_str, 10) catch null;
                    } else if (std.mem.startsWith(u8, trimmed, "seq:")) {
                        const seq_str = std.mem.trim(u8, trimmed["seq:".len..], " \t");
                        enr_fields.seq = std.fmt.parseInt(u64, seq_str, 10) catch null;
                    } else {
                        // Custom field
                        const colon_pos = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                        const key = try self.allocator.dupe(u8, std.mem.trim(u8, trimmed[0..colon_pos], " \t"));
                        const value_start = trimmed[colon_pos + 1 ..];
                        const value = if (std.mem.startsWith(u8, value_start, " \""))
                            value_start[2 .. std.mem.indexOf(u8, value_start[2..], "\"") orelse value_start.len]
                        else
                            std.mem.trim(u8, value_start, " \t");

                        try custom_fields.append(types.CustomField{
                            .key = key,
                            .value = try self.allocator.dupe(u8, value),
                        });
                    }
                }
            }
        }

        // Save last validator
        if (current_validator) |*validator| {
            if (in_enr_fields) {
                enr_fields.custom = try custom_fields.toOwnedSlice();
                validator.enrFields = enr_fields;
            }
            try validators.append(validator.*);
        }

        return types.ValidatorConfigFile{
            .shuffle = shuffle orelse try self.allocator.dupe(u8, "roundrobin"),
            .validators = try validators.toOwnedSlice(),
        };
    }

    fn generateENRs(self: *Self, validators_config: types.ValidatorConfigFile) ![][]const u8 {
        var enrs = std.ArrayList([]const u8).init(self.allocator);

        for (validators_config.validators) |validator| {
            if (validator.enr) |existing_enr| {
                // Use pre-generated ENR
                const enr_copy = try self.allocator.dupe(u8, existing_enr);
                try enrs.append(enr_copy);
            } else if (validator.privkey) |privkey| {
                // Generate ENR from private key and fields
                const generated_enr = try self.generateENRFromPrivkey(privkey, validator.enrFields);
                try enrs.append(generated_enr);
            } else {
                return error.MissingENRData;
            }
        }

        return enrs.toOwnedSlice();
    }

    fn generateENRFromPrivkey(self: *Self, privkey: []const u8, enr_fields: ?types.ENRFields) ![]const u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();

        // Clean private key (remove 0x prefix if present)
        const clean_privkey = if (std.mem.startsWith(u8, privkey, "0x"))
            privkey[2..]
        else
            privkey;

        if (clean_privkey.len != 64) {
            return error.InvalidSecretKeyLength;
        }

        // Create signable ENR
        var signable_enr = enr.SignableENR.fromSecretKeyString(clean_privkey) catch {
            return error.ENRCreationFailed;
        };

        // Set ENR fields if provided
        if (enr_fields) |fields| {
            if (fields.ip) |ip| {
                const ip_addr = std.net.Ip4Address.parse(ip, 0) catch {
                    return error.InvalidIPAddress;
                };
                const ip_addr_bytes = std.mem.asBytes(&ip_addr.sa.addr);
                signable_enr.set("ip", ip_addr_bytes) catch {
                    return error.ENRSetIPFailed;
                };
            }

            if (fields.ip6) |ip6| {
                const ip6_addr = std.net.Ip6Address.parse(ip6, 0) catch {
                    return error.InvalidIP6Address;
                };
                const ip6_addr_bytes = std.mem.asBytes(&ip6_addr.sa.addr);
                signable_enr.set("ip6", ip6_addr_bytes) catch {
                    return error.ENRSetIP6Failed;
                };
            }

            if (fields.tcp) |tcp| {
                var tcp_bytes: [2]u8 = undefined;
                std.mem.writeInt(u16, &tcp_bytes, tcp, .big);
                signable_enr.set("tcp", &tcp_bytes) catch {
                    return error.ENRSetTCPFailed;
                };
            }

            if (fields.udp) |udp| {
                var udp_bytes: [2]u8 = undefined;
                std.mem.writeInt(u16, &udp_bytes, udp, .big);
                signable_enr.set("udp", &udp_bytes) catch {
                    return error.ENRSetUDPFailed;
                };
            }

            if (fields.quic) |quic| {
                var quic_bytes: [2]u8 = undefined;
                std.mem.writeInt(u16, &quic_bytes, quic, .big);
                signable_enr.set("quic", &quic_bytes) catch {
                    return error.ENRSetQUICFailed;
                };
            }

            if (fields.seq) |seq| {
                var seq_bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &seq_bytes, seq, .big);
                signable_enr.set("seq", &seq_bytes) catch {
                    return error.ENRSetSEQFailed;
                };
            }

            // Handle custom fields
            if (fields.custom) |custom| {
                for (custom) |field| {
                    // For custom fields, we assume they are hex strings
                    if (std.mem.startsWith(u8, field.value, "0x")) {
                        const hex_value = field.value[2..];
                        const bytes = try self.allocator.alloc(u8, hex_value.len / 2);
                        defer self.allocator.free(bytes);
                        _ = std.fmt.hexToBytes(bytes, hex_value) catch {
                            return error.InvalidCustomFieldValue;
                        };
                        signable_enr.set(field.key, bytes) catch {
                            return error.ENRSetCustomFailed;
                        };
                    } else {
                        // Treat as raw bytes
                        signable_enr.set(field.key, field.value) catch {
                            return error.ENRSetCustomFailed;
                        };
                    }
                }
            }
        }

        try enr.writeSignableENR(writer, &signable_enr);
        return buffer.toOwnedSlice();
    }

    fn calculateValidatorIndices(self: *Self, validators_config: types.ValidatorConfigFile) !std.StringHashMap([]u32) {
        var result = std.StringHashMap([]u32).init(self.allocator);

        // Calculate total validator count
        var total_validators: u32 = 0;
        for (validators_config.validators) |validator| {
            total_validators += validator.count;
        }

        // Distribute indices based on shuffle strategy
        const shuffle_str = std.mem.trim(u8, validators_config.shuffle, " \t\n\r\"");
        if (std.mem.eql(u8, shuffle_str, "roundrobin")) {
            var current_index: u32 = 0;
            for (validators_config.validators) |validator| {
                var indices = std.ArrayList(u32).init(self.allocator);
                for (0..validator.count) |i| {
                    _ = i; // Suppress unused variable warning
                    try indices.append(current_index);
                    current_index += 1;
                }
                const indices_slice = try indices.toOwnedSlice();
                try result.put(validator.name, indices_slice);
            }
        } else {
            return error.UnsupportedShuffleStrategy;
        }

        return result;
    }

    fn writeConfigOutput(self: *Self, output_dir: []const u8, config: types.GenesisConfig) !void {
        const config_path = try std.fmt.allocPrint(self.allocator, "{s}/config.yaml", .{output_dir});
        defer self.allocator.free(config_path);

        const file = try std.fs.cwd().createFile(config_path, .{});
        defer file.close();

        const writer = file.writer();
        try writer.print("# Genesis Settings\n", .{});
        try writer.print("GENESIS_TIME: {d}\n", .{config.GENESIS_TIME});
        try writer.print("\n# Validator Settings\n", .{});
        try writer.print("VALIDATOR_COUNT: {d}\n", .{config.VALIDATOR_COUNT});
    }

    fn writeNodesOutput(self: *Self, output_dir: []const u8, enrs: [][]const u8) !void {
        const nodes_path = try std.fmt.allocPrint(self.allocator, "{s}/nodes.yaml", .{output_dir});
        defer self.allocator.free(nodes_path);

        const file = try std.fs.cwd().createFile(nodes_path, .{});
        defer file.close();

        const writer = file.writer();
        for (enrs) |enr_str| {
            try writer.print("- {s}\n", .{enr_str});
        }
    }

    fn writeValidatorsOutput(self: *Self, output_dir: []const u8, validator_indices: std.StringHashMap([]u32)) !void {
        const validators_path = try std.fmt.allocPrint(self.allocator, "{s}/validators.yaml", .{output_dir});
        defer self.allocator.free(validators_path);

        const file = try std.fs.cwd().createFile(validators_path, .{});
        defer file.close();

        const writer = file.writer();
        var iterator = validator_indices.iterator();
        while (iterator.next()) |entry| {
            try writer.print("{s}:\n", .{entry.key_ptr.*});
            for (entry.value_ptr.*) |index| {
                try writer.print("    - {d}\n", .{index});
            }
        }
    }

    fn generateGenesisState(self: *Self, output_dir: []const u8, config: types.GenesisConfig) !void {
        // Use existing genesis state generation
        const genesis_spec = types.GenesisSpec{
            .genesis_time = config.GENESIS_TIME,
            .num_validators = config.VALIDATOR_COUNT,
        };

        const genesis_state = try sftFactory.genGenesisState(self.allocator, genesis_spec);

        // Write genesis state to files
        try self.writeGenesisState(output_dir, genesis_state);
        try self.writeGenesisBlock(output_dir, genesis_state);
    }

    fn writeGenesisState(self: *Self, output_dir: []const u8, genesis_state: types.BeamState) !void {
        // Write SSZ format
        const state_ssz_path = try std.fmt.allocPrint(self.allocator, "{s}/state.ssz", .{output_dir});
        defer self.allocator.free(state_ssz_path);

        const state_ssz_file = try std.fs.cwd().createFile(state_ssz_path, .{});
        defer state_ssz_file.close();

        var state_ssz_buffer = std.ArrayList(u8).init(self.allocator);
        defer state_ssz_buffer.deinit();

        try ssz.serialize(types.BeamState, genesis_state, &state_ssz_buffer);
        try state_ssz_file.writeAll(state_ssz_buffer.items);

        // Write JSON format
        const state_json_path = try std.fmt.allocPrint(self.allocator, "{s}/state.json", .{output_dir});
        defer self.allocator.free(state_json_path);

        const state_json_file = try std.fs.cwd().createFile(state_json_path, .{});
        defer state_json_file.close();

        const state_json = try json.stringifyAlloc(self.allocator, genesis_state, .{});
        defer self.allocator.free(state_json);

        try state_json_file.writeAll(state_json);
    }

    fn writeGenesisBlock(self: *Self, output_dir: []const u8, genesis_state: types.BeamState) !void {
        const genesis_block = try sftFactory.genGenesisBlock(self.allocator, genesis_state);

        // Write SSZ format
        const block_ssz_path = try std.fmt.allocPrint(self.allocator, "{s}/genesis.ssz", .{output_dir});
        defer self.allocator.free(block_ssz_path);

        const block_ssz_file = try std.fs.cwd().createFile(block_ssz_path, .{});
        defer block_ssz_file.close();

        var block_ssz_buffer = std.ArrayList(u8).init(self.allocator);
        defer block_ssz_buffer.deinit();

        try ssz.serialize(types.BeamBlock, genesis_block, &block_ssz_buffer);
        try block_ssz_file.writeAll(block_ssz_buffer.items);

        // Write JSON format
        const block_json_path = try std.fmt.allocPrint(self.allocator, "{s}/genesis.json", .{output_dir});
        defer self.allocator.free(block_json_path);

        const block_json_file = try std.fs.cwd().createFile(block_json_path, .{});
        defer block_json_file.close();

        const block_json = try json.stringifyAlloc(self.allocator, genesis_block, .{});
        defer self.allocator.free(block_json);

        try block_json_file.writeAll(block_json);
    }
};

// Error types for genesis generation
pub const GenesisError = error{
    MissingENRData,
    InvalidSecretKeyLength,
    InvalidIPAddress,
    InvalidIP6Address,
    ENRCreationFailed,
    ENRSetIPFailed,
    ENRSetIP6Failed,
    ENRSetTCPFailed,
    ENRSetUDPFailed,
    ENRSetQUICFailed,
    ENRSetSEQFailed,
    ENRSetCustomFailed,
    InvalidCustomFieldValue,
    UnsupportedShuffleStrategy,
};
