<p align="center"><a href="https://github.com/blockblaz/zeam"><img width="500" title="Zeam" src='assets/zeam-logo.png' /></a></p>

# zeam - Zig Beam Client

Beam Chain is a futuristic ZK based Ethereum Consensus Protocol first [unveiled in Devcon 7 Bangkok Thailand, Nov 2024](https://www.youtube.com/watch?v=Gjuenkv1zrw)
and is meant to upgrade the current Beacon Chain when ready. Zeam is its production grade implementation (wip).

The heart of Beam Chain is to massively scale and decentralize ethereum consensus with provable and verifiable
protocol via ZK-VMs but also bundles some of the other disruptive ideas and learnings on ethereum consensus which 
could be a bit harder to incrementally implement on the current Beacon Chain.

## Beam Chain

[Beam Chain Developments & Resources](./resources/beam.md)

## Client Development

As is the ethos of ethereum community, beam protocol and specs will be developed in open. Zeam will not only
translate those specs to an production grade zig client but also actively contribute to development of those
specs.

We also will collaborate actively with other Beam clients and collectively will push the protocol to maturity
for consideration and deployment to ethereum blockchain.

We are currently doing various POCs/libs development:

 - [POC of zig run time](https://github.com/blockblaz/zeam-runtime) with various ZK-VMs.
 - [Snappy](https://github.com/blockblaz/zig-snappy) & [Snappy frames](https://github.com/blockblaz/snappyframesz)
 - [Zig <> rust libp2p interops](https://github.com/blockblaz/zig-libp2p-pocs)
 - [Zig SSZ!](https://github.com/blockblaz/ssz.zig)
 - [Hash Signatures](https://github.com/blockblaz/hash-sigz)

And all of these efforts culminating in a [ZEAM POC](./resources/zeam.md) with which we hope to aid in Beam Spec
research especially with state transition proving.

As we go along, we will also be maintaining important [resources](./resources/) related to beam protocol, ZK and
ZK-VMs, and quantum security & updates.

### Zig Ecosystem

Zig despite being relatively new is an upcoming ecosystem stack for ethereum protocol. We will aim to further push
the stack towards maturity via our modular client approach as well as independent libraries development and
contribution.

Please reach out to us if you are actively engaged in developing a library in the ecosystem that you may think
we can use and/or contribute to.

### Zeam community

Please join us on our community to take part in conversations around Beam Protocol and Zeam Client:

- [zeam community](https://t.me/zeamETH) telegram group
- [zeamETH](https://x.com/zeamETH) X(formerly twitter) handle

### Contributions

Zeam will welcome opensource contributions that meaningfully further the development of Zeam client. Keep Watching
out for this space for annoucements on the same or reach out to us via our [community telegram group](https://t.me/zeamETH)

### Build instructions


#### Prerequisites

 - Zeam requires zig version 0.14.1 to build.
 - Zeam requires Rust 1.85+ to be able to build the rust connections to various zkvms
 - The default prover is now [risc0](github.com/risc0/risc0) and it needs to be [installed](https://dev.risczero.com/api/zkvm/install).

#### Build

In order to build the transition functions (one for each supported zkvm), as well as the whole client, type:

```
> zig build -Doptimize=ReleaseFast
```

at the root of the repository.

#### Running the prover demo

```
> zig build -Doptimize=ReleaseFast install run -- prove
```

### Reporting Issues

Open an [issue or a bug](https://github.com/blockblaz/zeam/issues/new) or else talk to us via our [community telegram group](https://t.me/zeamETH).
