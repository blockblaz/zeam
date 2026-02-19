<p align="center"><a href="https://github.com/blockblaz/zeam"><img width="500" title="Zeam" src='assets/zeam-logo.png' /></a></p>

[![CI](https://github.com/blockblaz/zeam/actions/workflows/ci.yml/badge.svg)](https://github.com/blockblaz/zeam/actions/workflows/ci.yml)
[![risc0](https://github.com/blockblaz/zeam/actions/workflows/risc0.yml/badge.svg)](https://github.com/blockblaz/zeam/actions/workflows/risc0.yml)

# Zeam — Zig Beam Client

Zeam is a production-grade implementation (work-in-progress) of the [Beam Chain](https://www.youtube.com/watch?v=Gjuenkv1zrw) — a ZK-based Ethereum Consensus Protocol unveiled at Devcon 7 Bangkok (November 2024). Beam Chain is designed to upgrade the current Beacon Chain by massively scaling and decentralizing Ethereum consensus through provable, ZK-VM-backed state transitions.

---

## Table of Contents

- [Overview](#overview)
- [Beam Chain](#beam-chain)
- [Client Architecture](#client-architecture)
- [Package Structure](#package-structure)
- [ZK Prover Support](#zk-prover-support)
- [Libraries & Ecosystem](#libraries--ecosystem)
- [Build Instructions](#build-instructions)
- [Running a Local Devnet](#running-a-local-devnet)
- [Testing](#testing)
- [Community & Contributions](#community--contributions)
- [Reporting Issues](#reporting-issues)

---

## Overview

Beam Chain introduces several disruptive improvements to Ethereum consensus that are difficult to implement incrementally on the current Beacon Chain:

- **ZK-provable state transitions** — every state transition can be proven and verified by a ZK-VM
- **Quantum-resistant cryptography** — hash-based signatures (XMSS) replacing BLS
- **Decentralized consensus** — designed to scale and decentralize at the protocol level

Zeam translates these specs into a production-grade Zig client, actively contributing to the development of the Beam protocol alongside other client teams.

---

## Beam Chain

- [Beam Chain Developments & Resources](./resources/beam.md)
- [Zeam & Beam Wiki](https://github.com/blockblaz/zeam/wiki)
- [Beam Chain Devcon 7 Announcement](https://www.youtube.com/watch?v=Gjuenkv1zrw)

---

## Client Architecture

Zeam's architecture closely mirrors the Beacon Chain client structure, adapted for Beam's ZK-centric design. The client is built modularly, with each concern separated into its own package.

### Development Status

The team is currently building and validating foundational POCs and libraries before composing them into a full client:

| Area | Status |
|------|--------|
| ZK-VM state transition proving | Active POC |
| libp2p networking (Zig ↔ Rust) | POC complete |
| SSZ serialization | Library available |
| Hash-based signatures (XMSS) | In development |
| Snappy compression | Library available |
| Full client integration | Upcoming |

Refer to [ZEAM POC](./resources/zeam.md) for detailed documentation on the current POC scope and design.

---

## Package Structure

The `pkgs/` directory contains the modular components of the Zeam client:

| Package | Description |
|---------|-------------|
| `pkgs/state-transition` | Core state transition logic (Zig) |
| `pkgs/state-transition-runtime` | RISC-V binary executed inside ZK-VMs |
| `pkgs/state-proving-manager` | Orchestrates ZK proving and verification |
| `pkgs/node` | Main node lifecycle and coordination |
| `pkgs/network` | libp2p-based P2P networking |
| `pkgs/api` | HTTP API layer |
| `pkgs/cli` | Command-line interface |
| `pkgs/database` | Persistent storage (RocksDB) |
| `pkgs/types` | Shared Beam/Zeam data types |
| `pkgs/spectest` | Spec test framework |
| `pkgs/metrics` | Prometheus-compatible metrics |
| `pkgs/xmss` | Hash-based signature scheme |
| `pkgs/key-manager` | Key management utilities |
| `pkgs/params` | Protocol parameters |
| `pkgs/configs` | Node configuration |
| `pkgs/utils` | Shared utilities |
| `pkgs/tools` | Developer tooling |

---

## ZK Prover Support

Zeam supports multiple ZK-VMs for state transition proving:

| Prover | Status | Notes |
|--------|--------|-------|
| [risc0](https://github.com/risc0/risc0) v3.0.3 | Supported | Requires external toolchain |
| [OpenVM](https://github.com/openvm-org/openvm) | Supported | Self-contained, no toolchain needed |

---

## Libraries & Ecosystem

Zeam is developing and contributing to the Zig Ethereum ecosystem. These libraries are used in and alongside the client:

| Library | Description |
|---------|-------------|
| [ssz.zig](https://github.com/blockblaz/ssz.zig) | SSZ serialization with configurable hash function |
| [zig-snappy](https://github.com/blockblaz/zig-snappy) / [snappyframesz](https://github.com/blockblaz/snappyframesz) | Snappy compression |
| [zig-libp2p-pocs](https://github.com/blockblaz/zig-libp2p-pocs) | Zig ↔ Rust libp2p interop |
| [hash-sigz](https://github.com/blockblaz/hash-sigz) | Hash-based signature schemes |
| [zeam-runtime](https://github.com/blockblaz/zeam-runtime) | ZK-VM runtime POC |

If you are developing a library in the Zig ecosystem that could benefit Zeam, please reach out via [Telegram](https://t.me/zeamETH).

---

## Build Instructions

### Prerequisites

- **Zig** `0.15.2`
- **Rust** `1.85+` (required for ZK-VM Rust bindings)
- **risc0 toolchain** (only if using risc0 prover): `rzup install r0vm 3.0.3`
  - Install guide: https://dev.risczero.com/api/zkvm/install
- **OpenVM** is self-contained — no additional toolchain required

### Building

Build all transition functions and the full client:

```bash
zig build -Doptimize=ReleaseFast
```

To include the git version in the binary:

```bash
zig build -Doptimize=ReleaseFast -Dgit_version="$(git rev-parse --short HEAD)"
```

### Running the Prover Demo

```bash
zig build -Doptimize=ReleaseFast install run -- prove
```

### Docker

Docker images are built in CI using `Dockerfile.prebuilt`, which packages pre-built binaries. This avoids intermittent failures caused by a [Zig HTTP connection pool bug](https://github.com/ziglang/zig/issues/21316) when building inside Docker.

**Build a Docker image locally:**

```bash
# Build zeam natively first
zig build -Doptimize=ReleaseFast -Dgit_version="$(git rev-parse --short HEAD)"

# Then create Docker image with pre-built binary
docker build -f Dockerfile.prebuilt -t zeam:local .
```

**Build with OCI labels for registry publishing:**

```bash
docker build -f Dockerfile.prebuilt \
  --build-arg GIT_COMMIT=$(git rev-parse HEAD) \
  --build-arg GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD) \
  -t blockblaz/zeam:latest .
```

---

## Running a Local Devnet

To run a local devnet with multiple nodes for testing and development, see the [Local Devnet Setup Guide](./pkgs/cli/test/fixtures/README.md), which covers a 2-node setup with finalization.

Alternatively, use the [lean-quickstart](https://github.com/blockblaz/lean-quickstart) submodule:

```bash
git submodule update --init lean-quickstart
```

This provides a handy CLI tool to spin up two nodes for local interop.

### Checkpoint Sync

Zeam supports checkpoint sync for faster initial synchronization. Start a node from a trusted finalized checkpoint state using the `--checkpoint-sync-url` flag. See the [Local Devnet Setup Guide](./pkgs/cli/test/fixtures/README.md#checkpoint-sync) for full documentation.

---

## Testing

| Scenario | Guide |
|----------|-------|
| Test blocks by root (parent sync) | [parent-sync.md](./resources/parent-sync.md) |
| Test checkpoint sync | [checkpoint-sync.md](./resources/checkpoint-sync.md) |
| Spec test framework | [spec-test-framework.md](./resources/spec-test-framework.md) |

---

## Community & Contributions

Join the conversation around Beam Protocol and Zeam client:

- [Telegram community](https://t.me/zeamETH)
- [X / Twitter (@zeamETH)](https://x.com/zeamETH)
- [Zeam & Beam Wiki](https://github.com/blockblaz/zeam/wiki)
- [Community calls archive](https://github.com/blockblaz/zeam-community/issues?q=is%3Aissue+state%3Aclosed)

Zeam welcomes open-source contributions that meaningfully advance the client. Watch for announcements in the community or reach out directly via [Telegram](https://t.me/zeamETH).

---

## Reporting Issues

Open a [GitHub issue](https://github.com/blockblaz/zeam/issues/new) or reach out via the [Telegram community group](https://t.me/zeamETH).
