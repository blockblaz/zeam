# Migrating off the Rust libp2p-glue

This package today consumes libp2p via a Rust crate (`rust/libp2p-glue`) over
an FFI surface declared in `ethlibp2p.zig`. A pure-Zig replacement landed on
this branch as `ethlibp2p_v2.zig`, built on top of
[`zig-libp2p`](https://github.com/ch4r10t33r/zig-libp2p) v0.1.0.

## Why

- One Zig binary instead of Zig + a Rust static lib + an FFI boundary.
- Removes 5,700 lines of Rust glue + the Cargo/cbindgen build step.
- The Zig stack carries its own observability (mesh-peers gauge,
  command-drop counter with the `network_id, reason` labels zeam already
  publishes), so the Prometheus exporter doesn't change shape.
- Audit-confirmed equivalence for every FFI surface zeam consumes today
  (the comparison report is in `zig-libp2p`'s PR #109 description).

## What landed in this PR

1. **Dep wiring.** `build.zig.zon` pins `zig_libp2p` to v0.1.0; `build.zig`
   imports `zig_libp2p` into the network module so v2 can use it without
   touching the rest of the workspace.
2. **`ethlibp2p_v2.zig`.** A skeleton `EthLibp2pV2` that:
   - Owns a `zig_libp2p.host.Host` (bundles Swarm + Gossipsub + ReqResp +
     ConnectionManager).
   - Mirrors the public `init / deinit / publish / subscribe /
     subscribeReqResp / subscribePeerEvents` entry points so consumers
     don't change shape.
   - Drives a background event-drain loop matching the Rust glue's
     callback fan-out.
   - Compiles against zeam's existing `interface.zig` types — no
     consumer-side rewrite required to flip a network slot over.
3. **The legacy path is untouched.** `ethlibp2p.zig` (the Rust-FFI
   consumer) compiles and runs exactly as before. Embedders flip one
   network slot at a time by constructing `EthLibp2pV2` instead of
   `EthLibp2p`; the rest of the node keeps consuming the same handler
   shapes.

## What still has to happen on this branch

The skeleton compiles but does not yet run end-to-end. Each bullet below is
sized to be one focused commit on this branch; none of them block other
zeam work.

| Commit | What it does | Estimated size |
|---|---|---|
| `feat(v2): wire QuicListener` | Bring up `zl.transport.quic_endpoint.QuicListener` per `listen_address`. Plumb `on_inbound_stream_ready` through multistream-select into Host's `handleGossipRpc` / `registerInboundReqRespChannel`. | ~250 LOC |
| `feat(v2): gossip frame coding` | Topic-keyed snappy + SSZ encode/decode (mirrors `gossipMessageToFrame` from the legacy path). | ~150 LOC |
| `feat(v2): handler dispatch` | Fill in the `dispatch*` stubs to translate `Swarm.Event` variants into `interface.GossipMessage` / `ReqRespRequest` / peer events and invoke the registered handlers. | ~200 LOC |
| `feat(v2): bootnode dial` | At init time, parse `connect_peers` and call `host.registerKnownPeer` for each; tick `connection_manager` on the driver thread. | ~80 LOC |
| `feat(v2): node3 sync parity` | Re-run the issue #942 corruption regressions against v2; carry forward the publish-side forensic log line. | ~50 LOC + test data |
| `feat(v2): metrics parity` | Wire the existing `zeam_libp2p_swarm_command_dropped_total` and `lean_gossip_mesh_peers` Prometheus scrapers to read from `zig_libp2p.metrics.Metrics` instead of the Rust FFI getters. | ~80 LOC |
| `test(v2): full end-to-end against zig-libp2p sister node` | Two `EthLibp2pV2` instances exchanging blocks over real QUIC sockets. | ~200 LOC |

Once `feat(v2): node3 sync parity` is green, a follow-up commit removes:

- `rust/libp2p-glue/` (entire directory; ~5,700 LOC of Rust)
- The Rust glue wiring in `build.zig` (~30 LOC)
- The legacy `ethlibp2p.zig` (~2,400 LOC of Zig FFI)

Net change after the final commit: **−8,100 LOC, +800 LOC.**

## Why this PR doesn't do it all in one shot

Each commit above is independently verifiable against the existing test
suite and the issue #942 fixtures. Landing them one by one keeps the
`feat/replace-libp2p-glue` branch reviewable and means a single regression
doesn't block the whole migration. The skeleton in this PR is the smallest
diff that proves the wiring compiles and that the public consumer surface
doesn't need to change.

## Why not just swap directly?

Three reasons:

1. **The Rust glue carries node3-sync corruption fixes** (issue #942) that
   have to be reproduced on the Zig side before we can delete the Rust
   path. Doing the swap on top of a skeleton lets us run both paths
   side-by-side during validation.
2. **zig-libp2p's `tls.nonblock` TCP path isn't shipped yet** (blocked on
   upstream zquic re-exporting the type; see `zig-libp2p` PR #105 partial
   close of #86). For QUIC-only deployments this is fine; TCP-only
   deployments will need to wait or fall back to the legacy path.
3. **Multi-network slot accounting.** The Rust glue manages up to 3
   network slots in a `static [NetworkSlot; MAX_NETWORKS]` array; the
   Zig path makes each slot its own `EthLibp2pV2` instance owned by the
   embedder. The shape change is small but worth landing in its own
   commit on this branch.
