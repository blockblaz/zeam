//! Zeam-side adapter for the experimental **ethp2p** parallel RS-broadcast
//! transport (mirrors ethlambda's `Ethp2pBroadcast`). It runs a separate QUIC
//! network *alongside* libp2p/gossipsub: every outbound gossip publish is teed
//! into a `zig_ethp2p` `BroadcastNode`, Reed-Solomon erasure-coded, and pushed
//! to ethp2p peers; delivered messages are snappy-decompressed, SSZ-decoded,
//! and reinjected into the node's gossip handler.
//!
//! Compiled only under `-Dethp2p=true` (see `ethp2p.zig`, which otherwise
//! selects `ethp2p_broadcast_stub.zig`). Experimental and off by default:
//! single-peer-correct outbound, no peer auth, no discovery-driven peering.

const std = @import("std");
const zig_ethp2p = @import("zig_ethp2p");
const interface = @import("interface.zig");
const config_mod = @import("ethp2p_config.zig");
const snappyz = @import("snappyz");
const ssz = @import("ssz");
const types = @import("@zeam/types");

const BroadcastNode = zig_ethp2p.node.broadcast_host.BroadcastNode;
const BroadcastNodeConfig = zig_ethp2p.node.broadcast_host.BroadcastNodeConfig;
const RsConfig = zig_ethp2p.layer.rs_init.RsConfig;
const FullMessage = zig_ethp2p.node.broadcast_host.FullMessage;

pub const Config = config_mod.Config;

const log = std.log.scoped(.ethp2p);

/// RS channels, named to match `GossipTopicKind` tag names so a channel id
/// round-trips to/from `@tagName`.
const channel_names = [_][]const u8{ "block", "aggregation", "attestation" };

/// Snappy decode ceiling for delivered payloads.
const max_decode: usize = 50 * 1024 * 1024;

pub const Ethp2pBroadcast = struct {
    allocator: std.mem.Allocator,
    backend: interface.NetworkInterface,
    node: *BroadcastNode,

    pub fn start(
        allocator: std.mem.Allocator,
        backend: interface.NetworkInterface,
        cfg: Config,
    ) !*Ethp2pBroadcast {
        const node = try BroadcastNode.init(allocator, .{
            .local_peer_id = cfg.local_peer_id,
            .listen_addr = cfg.listen_addr,
            .server_certificate_pem_path = cfg.server_certificate_pem_path,
            .server_private_key_pem_path = cfg.server_private_key_pem_path,
            // Bounded so an unreachable static peer at startup can't hang the
            // node for long.
            .handshake_poll_rounds = 4000,
        });
        errdefer node.deinit();

        const rs_cfg = RsConfig.default();
        for (channel_names) |name| {
            try node.addChannel(name, rs_cfg, cfg.sub_capacity);
        }

        // Best-effort dial of static peers; failures are logged, not fatal.
        for (cfg.static_peers) |peer| {
            node.connect(peer, cfg.server_name) catch |e| {
                log.warn("ethp2p: dial {s} failed: {any}", .{ peer, e });
            };
        }

        const self = try allocator.create(Ethp2pBroadcast);
        self.* = .{ .allocator = allocator, .backend = backend, .node = node };

        log.info(
            "ethp2p broadcast started: peer_id={s} listen={?s} static_peers={d}",
            .{ cfg.local_peer_id, cfg.listen_addr, cfg.static_peers.len },
        );
        return self;
    }

    pub fn deinit(self: *Ethp2pBroadcast) void {
        self.node.deinit();
        self.allocator.destroy(self);
    }

    /// Tee an outbound gossip message into the RS-broadcast network. Best-effort
    /// — never propagates errors to the libp2p publish path.
    pub fn publishGossip(self: *Ethp2pBroadcast, msg: *const interface.GossipMessage) void {
        const ssz_bytes = msg.serialize(self.allocator) catch |e| {
            log.debug("ethp2p tee: ssz serialize failed: {any}", .{e});
            return;
        };
        defer self.allocator.free(ssz_bytes);

        // message_id = hex(sha256(ssz_bytes)) — matches ethlambda's keying.
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ssz_bytes, &digest, .{});
        const mid = std.fmt.bytesToHex(digest, .lower);

        // RS payload is the snappy-compressed gossip body (same bytes libp2p
        // would put on the wire).
        const payload = snappyz.encode(self.allocator, ssz_bytes) catch |e| {
            log.debug("ethp2p tee: snappy encode failed: {any}", .{e});
            return;
        };
        defer self.allocator.free(payload);

        const channel = @tagName(std.meta.activeTag(msg.*));
        self.node.publish(channel, &mid, payload) catch |e| {
            log.debug("ethp2p tee: publish failed channel={s}: {any}", .{ channel, e });
            return;
        };
        log.debug(
            "ethp2p tee: channel={s} mid={s} ssz={d} payload={d}",
            .{ channel, &mid, ssz_bytes.len, payload.len },
        );
    }

    /// Drive the RS-broadcast QUIC engine and reinject any reconstructed
    /// messages back into the node's gossip handler.
    pub fn tick(self: *Ethp2pBroadcast, now_ms: i64) void {
        self.node.tick(now_ms) catch |e| {
            log.debug("ethp2p tick: {any}", .{e});
        };
        for (channel_names) |name| {
            while (self.node.poll(name)) |fm| {
                self.deliver(name, fm);
                self.node.freeMessage(fm);
            }
        }
    }

    /// Snappy-decompress + SSZ-decode a delivered RS message and hand it to the
    /// gossip handler, exactly as the libp2p inbound path does. Best-effort.
    fn deliver(self: *Ethp2pBroadcast, channel: []const u8, fm: FullMessage) void {
        const kind = std.meta.stringToEnum(interface.GossipTopicKind, channel) orelse return;

        const uncompressed = snappyz.decodeWithMax(self.allocator, fm.data, max_decode) catch |e| {
            log.debug("ethp2p deliver: snappy decode failed channel={s}: {any}", .{ channel, e });
            return;
        };
        defer self.allocator.free(uncompressed);

        var message: interface.GossipMessage = switch (kind) {
            .block => blk: {
                var sb: types.SignedBlock = undefined;
                ssz.deserialize(types.SignedBlock, uncompressed, &sb, self.allocator) catch return;
                break :blk .{ .block = sb };
            },
            .aggregation => blk: {
                var agg: types.SignedAggregatedAttestation = undefined;
                ssz.deserialize(types.SignedAggregatedAttestation, uncompressed, &agg, self.allocator) catch return;
                break :blk .{ .aggregation = agg };
            },
            .attestation => blk: {
                var att: types.SignedAttestation = undefined;
                ssz.deserialize(types.SignedAttestation, uncompressed, &att, self.allocator) catch return;
                // The gossip subnet id lives in the libp2p topic, not the SSZ
                // body, and the ethp2p channel does not carry it — reinject on
                // subnet 0 (best-effort; cross-process attestation delivery is
                // out of scope for this experimental adapter).
                break :blk .{ .attestation = .{ .subnet_id = 0, .message = att } };
            },
        };
        defer message.deinit();

        self.backend.gossip.onGossipFn(self.backend.gossip.ptr, &message, "ethp2p") catch |e| {
            log.debug("ethp2p deliver: onGossip failed channel={s}: {any}", .{ channel, e });
        };
    }
};
