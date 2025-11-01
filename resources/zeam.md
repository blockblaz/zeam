# Zeam

[Zeam Calls](https://github.com/blockblaz/zeam-community/issues?q=is%3Aissue%20state%3Aclosed)

[Zeam & Beam Wiki](https://github.com/blockblaz/zeam/wiki)

## Zeam Client POC

While the Beam research community is working on Beam specs, we at Zeam are aiming to have a POC of one of
the most (if not the most) critical elements of Beam Protocol:

*State Transition Proving and non Enshrined Proofs*

### Zeam Client Structure

Zeam client structure closely follows Beacon client structure i.e. essential elements of Ethereum POS

### POC components and interaction

The Zeam POC is very focused on running and verifying the state transition pipeline and hence dispenses with
all other moving parts of a Beacon like POS protocol.

#### Simplified Setup

- No validators/deposit/beacon processing
  - Blocks still have proposer_index to assign any dummy value
  - genesis validators root is also dummy

- Only very basic state transition
  - empty epoch transition
  - only block's parent_root matched against state's `latest_block_header` hash tree root
  - Round robin shuffling based on a fixed user provided node id
  - Very primive genesis state

- No execution interaction and hence no execution payload header

- P2P simplifications
  - POC Stage 0: Single Node Run with no p2p interactions
  - POC Stage 1: Two Node runs with libp2p peering, no req/resp syncing only gossip
  - POC Stage 2: Two Node runs with libp2p peering with req/resp syncing

- Small networks
  - All/Most Data structures maintained in memory
  - Small & Fixed Number of nodes

- Slot times
  - Very high slot times

- Proving mechanics
- Stage 0: Syncronous proving with block publishing
- Stage 1: Async proving published following block
- Stage 2: Real time proving available next block

- Block import & forkchoice
- Very primited forkchoice
- Weighted by constant weight - 1 each block

- No real/production/sophisticated POS/Beacon parts
  - No beacon/other Apis
  - No crypto validation/verifications
    - Signatures
    - Gossip
  - No production optimizations
    - SSZ Tree based structures and optimizations
  - No DA
    - no blobs
    - no peerdas
  - No lightclient protocol and so on...

Once we have the basic state transition working, we will start incrementally adding the functionality to build
out an actual client. However at all times, we will follow a very basic Agile fundamental of keeping out client
functional and testable as well as add unit, end to end as well as E2E tests runnable in CI.

#### Zeam State transition components

1. `pkgs/state-transition`

 ```zig
  pub fn apply_transition(state: types.BeamState, block: types.BeamBlock, .{}) !void
 ```

- Implements/verifies the basic state transistion in zig
- Imported and used by the `riscv5` runtime binary whose execution ZK-VMs will prove

2. `pkgs/state-transition-runtime`

 ```zig
 // implements riscv5 runtime that runs in zkvm on provided inputs and witnesses to execute
 // and prove the state transition as imported from `pkgs/state-transition`
 pub fn main() noreturn
 ```

- a riscv5 binary that imports and execute the state transition implemented in `pkgs/state-transition`
- inputs: pre state_root and block_root
- witnesses: pre state and block ssz serialized

Note that even block has been added as witness, so the proving can even be done just with block root and
pre state_root. A variant of this would be use full block for proving however that is not efficient and
one can always calculate and verify block root from the block. This is especially useful for verifying
the state transition

3. `pkgs/state-proving-manager`

 ```zig
   pub fn execute_transition(state: types.BeamState, block: types.BeamBlock, opts: ZKStateTransitionOpts) types.BeamSTFProof
```

- invoked to prove a block against a pre state
- invokes the requested ZK-VM for executing the `pkgs/state-transition-runtime` riscv5 binary with inputs and
    witnesses constructed from state and block
- returns the state transition proof

```zig
pub fn verify_transition(stf_proof: types.BeamSTFProof, state_root: types.Bytes32, block_root: types.Bytes32, opts: ZKStateTransitionOpts) !void
```

- verifies the state transition proof on a pre state root and block root
- invokes the requested ZK-VM for verifying the `pkgs/state-traansition-runtim` riscv5 binary with inputs constructed
  from state and block
- throws error if the verification fails

When a block is constructed, one may construct the ZK proofs for a targetted VM against the zeam state transition.
Now some VMs may also (eventually?) provide a post state result of executing it which would be very efficient for
a syncronous proving scenario in which case the post state can directly be constructed and used to complete block.
However that will also require deferring post state root checks for the Beam block.

For now, the block producer runs `stf` which from `pkgs/state-transition` and construct post state and there after
fills the post state root in the block and publish it. Proving the block is an independent function which the block
constructor can take up or leave to others to prove and publish in network.

For purposes of Zeam POC the block producer after producing the block fully also invokes the proving manager to produce
the ZK proofs. Note that the proving manager uses riscv5 binary from `pkgs/state-transition-runtime` which itself uses
the `pkgs/state-transition` to run and proof the the state transition. Similarly for verification.

Infact it would be easy enough to independently verify the state transition just by block root and state root with a
way to trust track/source these roots via a lightclient protocol.

#### Zeam POC pipeline
