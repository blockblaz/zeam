# Running zeam under the Shadow network simulator

`devnet5-shadow` is a self-contained setup for running a zeam devnet under the
[Shadow](https://shadow.github.io) discrete-event network simulator. It layers a
few Shadow-specific adjustments on top of the devnet5 line.

## What this branch adds

- **`-Dno-jemalloc` build option.** Drops the jemalloc global allocator and uses
  the system allocator instead. jemalloc's first-init reads `/etc/malloc.conf`
  via `readlink` while holding its non-recursive init lock; under Shadow that
  `readlink` is the shim's first intercepted syscall, whose lazy init calls
  `fopen` → `malloc` and re-enters jemalloc, self-deadlocking at startup
  (reported upstream as shadow/shadow#3763). The system allocator avoids it.
- **Vendored `quinn-udp` fallback** (`rust/patch/quinn-udp`, wired via
  `[patch.crates-io]`). Forces QUIC onto the plain `send_to`/`recv_from` path
  instead of GSO/GRO segmentation, control messages, and ECN — none of which
  Shadow fully emulates.
- **Single-threaded libp2p runtime** (`new_current_thread`). Shadow single-steps
  execution, so the multi-threaded tokio runtime is unnecessary here.

## Build

```sh
zig build -Dno-jemalloc -Doptimize=ReleaseSafe
```

Use at least `ReleaseSafe` (optimized, with runtime safety checks) — or
`-Doptimize=ReleaseFast` for maximum speed. The default prover (`dummy`) already
builds the multisig/leanMultisig devnet5 prover (no `-Dprover` needed), and the
`quinn-udp` patch applies automatically via the committed `[patch.crates-io]`.

**RAM note:** optimizing the ~240 MB prover staticlib is memory-hungry — LLVM can
need >28 GB and OOM a 32 GB host. On a constrained box, add swap (e.g. 16–24 GB)
or use a larger machine. Avoid `Debug` for real runs: it is unoptimized (much
slower under Shadow) and uses the leak-detecting allocator that never returns
freed pages to the OS, so node RSS ratchets up — treat it only as a last resort
on a very small host.

## Run

Shadow does not charge CPU time, so the recursive-STARK prover would otherwise
run "free" in virtual time, making the simulation unrepresentative. Model its
cost with the `--shadow-xmss-*-rate` node flags — each sleeps `n / rate`
nanoseconds of virtual time for an `n`-unit operation. Add them to the
`zeam node` args in your `shadow.yaml` (tune the rates to your measured prover
cost):

```
zeam node ... \
  --shadow-xmss-merge-rate 2 \
  --shadow-xmss-aggregate-signatures-rate 5 \
  --shadow-xmss-verify-aggregated-signatures-rate 100
```

Then run the simulation:

```sh
shadow shadow.yaml
```

## Expected result

A 4-node devnet boots and finalizes in lockstep 3SF (finalized = head − 3) at
4 s slots — e.g. `head=59 / justified=57 / finalized=56`. The first ~2 slots are
slow (QUIC peer connections + genesis warmup); after that it advances steadily.
An optimized (`ReleaseSafe`/`ReleaseFast`) build runs near or faster than
wall-clock; an unoptimized `Debug` build is several times slower per slot.
