# Devnet 5 — Aggregated Block Proof (Type-1 / Type-2 multisig)

**Date:** 2026-05-21
**Branch:** `devnet-5-spec-impl`
**Upstream spec:** leanSpec PR #717 "Aggregated block proof - devnet5" (head `1db9e4d0`)
**leanMultisig:** `anshalshukla/leanMultisig@devnet5-patched` (`f33a0775`), via `lean-multisig-py v0.0.5`

## Goal

Port leanSpec devnet 5 to zeam. The spec collapses per-attestation signature proofs
plus the proposer signature into a **single aggregated block proof**: a Type-2
multi-message multisignature carried as one `ByteList512KiB` blob on `SignedBlock`.

## Decisions (locked with user)

1. **Spec alignment:** adapt to Zig architecture, but logic must follow the spec exactly.
2. **Scope:** full devnet5 end-to-end on one branch (`devnet-5-spec-impl`), one release at the end.
3. **FFI source:** use exactly what leanSpec uses — `anshalshukla/leanMultisig@devnet5-patched`
   (`f33a0775`), pinned by `rev` in `rust/multisig-glue/Cargo.toml`.
4. **FFI style:** bytes-in / bytes-out (option B), because the upstream API is bytes-first
   (`compress_without_pubkeys() -> Vec<u8>`). Drop the opaque-handle pattern. This is a
   deliberate redesign — the current opaque-handle style is historical inheritance from
   PR #440 / devnet4, never a positive design choice.
5. **Migration:** hard cutover. Delete `AggregatedSignatureProof`. Fresh datadir required;
   no fork flag, no dual decoding, no SSZ-compat shim.
6. **Tests:** spectest fixtures (primary integration net) + focused unit tests on hot paths.
7. **No fallback paths:** follow the spec's primary path; failures are hard errors to
   investigate, never silently absorbed by an alternative path.
8. **test-config aggregation:** be consistent with the spec — build a test-scheme aggregation
   path so `leanEnv=test` fixtures with body attestations actually run (option B), instead of
   skipping them like devnet4 did. **Subject to the open build risk below.**

## Architecture

### Two proof shapes (mirror `subspecs/xmss/aggregation.py`)

- **Type-1** — many validators sign **one** message (one `AttestationData` root, or one
  block root). `{ participants: AggregationBits, proof: ByteList512KiB }`. Replaces
  `AggregatedSignatureProof`.
- **Type-2** — merge of N Type-1 proofs over **distinct** messages. `{ proof: ByteList512KiB }`,
  compact no-pubkeys form. Used only inside the block envelope.

### Block envelope

`SignedBlock { block, proof: ByteList512KiB }` — `proof` is the SSZ-encoded Type-2 binding
every body attestation plus the proposer's signature over the block root (proposer entry **last**).
`BlockSignatures` and `AttestationSignatures` are deleted.

### Block import data flow (strict spec, no fallback)

```
on_block:
  decode SignedBlock (SSZ); decode Type-2 from .proof
  verify_signatures: single verify_type_2 over all attestations + proposer
  state_transition
  for each body attestation: stamp AttestationData key into
        latest_known_aggregated_payloads with an EMPTY proof set
  deconstruct_block_into_store (mandatory):
     for each att where target.slot > justified.slot AND block_participants ⊄ local_union:
        split_type_2_by_msg → Type-1 component; restore participants from att bits
        if local partials exist: aggregate_type_1(component + partials) → combined
        else: combined = component
        write combined → latest_new_aggregated_payloads; drop superseded partials
        if aggregator: queue combined for gossip publish
  update_head
  publish queued aggregates (aggregator only)
```

### Key behavioural consequence

Block-imported attestations do **not** get fork-choice weight at import time. The recovered
Type-1s land in `latest_new_aggregated_payloads` and migrate to `latest_known` only via the
existing `acceptNewAttestationsUnlocked` rotation (intervals 0/4). `AttestationTracker` is
updated **only** through that existing payload→tracker pipeline — no eager bitfield write from
`onBlock`, no second source of truth. This matches the spec's deferred-weight design and is
intentional. Rationale: `split_type_2_by_msg` is a prover invocation (≈ a fresh Type-1
aggregation), so eager extraction on every import is wasteful; the spec amortizes it via the
`block_participants ⊄ local_union` skip and the existing rotation pipeline.

### Unchanged

protoarray + `AttestationTracker` (LMD-GHOST head selection over 3SF justify/finalize),
payload-map keys, gossip subnets, block-production fixed-point loop, `select_greedily`
set-cover, and our `StoredAggregatedPayload` metadata
(`source_payload_participants` / `source_gossip_participants`) which the Python spec
doesn't model but our aggregator pipeline needs.

## Per-layer design

### 1. Byte-list constant — `pkgs/xmss/src/aggregation.zig`

Delete `MAX_AGGREGATE_SIGNATURE_SIZE` (1 MiB) / `ByteListMiB`. Add
`MAX_AGGREGATE_PROOF_SIZE = 512*1024` / `ByteList512KiB`.

### 2. Types — `pkgs/types/src/aggregation.zig`, `block.zig`, `attestation.zig`

- `TypeOneMultiSignature { participants, proof }` (spec name kept — it's a crypto shape, not
  a Python convention). Methods: `init/deinit/aggregate/verify/selectGreedily/toJson`.
- `TypeTwoMultiSignature { proof }`. Methods: `init/deinit/aggregate/verify/splitByMessage/toJson`.
- `SignedBlock { block, proof: ByteList512KiB }`. Delete `BlockSignatures`,
  `AttestationSignatures`, `createBlockSignatures`.
- New `BlockProductionProofs { attestations, attestation_type1s: ArrayList(TypeOneMultiSignature) }`
  (in-memory product of block production; not SSZ). Replaces `AggregatedAttestationsResult`'s
  signature field.
- `SignedAggregatedAttestation.proof: TypeOneMultiSignature` (was `AggregatedSignatureProof`).
- Forkchoice payload maps: inner proof type → `TypeOneMultiSignature`; keep `StoredAggregatedPayload` wrapper.
- `MessageBinding { hash: [32]u8, slot: u32 }` helper for Type-2 verify slices.
- SSZ field order verified to match spec (participants,proof / proof / block,proof / data,proof).

### 3. FFI — `rust/multisig-glue/src/lib.rs`, `pkgs/xmss/src/aggregation.zig`

Cargo: pin `rec_aggregation`/`leansig_wrapper`/`backend` to `rev = f33a0775`.

Delete: `xmss_aggregate`, `xmss_verify_aggregated`, `xmss_verify_aggregated_batch`,
`xmss_aggregate_signature_to_bytes/from_bytes`, `xmss_free_aggregate_signature`, `AggregatedXMSS`.

Add (bytes-in/out, output via `(out_buf, out_cap, out_written)` → 0/-1/-2 protocol):
`xmss_aggregate_type_1`, `xmss_verify_type_1`, `xmss_verify_type_1_batch`,
`xmss_merge_type_1_to_type_2`, `xmss_split_type_2_by_msg`, `xmss_verify_type_2`.

Zig wrappers: `aggregateType1`, `verifyType1`, `verifyType1Batch`, `mergeType1ToType2`,
`splitType2ByMessage`, `verifyType2`. New `AggregationError` variants:
`ProofTooLarge`, `ProofDecodeFailed`, `Type1AggregateFailed`, `Type1VerifyFailed`,
`Type2MergeFailed`, `Type2SplitFailed`, `Type2VerifyFailed`.

Threading: all wrappers are pure Zig + extern; callers MUST keep them off libxev (doc comment
on each). Re-export the new symbol set through `rust/zeam-glue`.

### 4. Block production — `pkgs/node/src/chain.zig`, `validator_client.zig`

- `produceBlock` returns `{ block, blockRoot, attestation_type1s: ArrayList(TypeOneMultiSignature),
  post_state }` — per-attestation Type-1s, no merge. Mirrors `produce_block_with_signatures`.
- `validator_client._sign_block` equivalent: sign block root (proposal key) → wrap as singleton
  Type-1 → `mergeType1ToType2([*attestation_type1s, proposer_type1], pks_per_part)` →
  SSZ-encode → `SignedBlock.proof`. Proposer entry **last**.
- New `chain.borrowStateForSigning(root)` (RAII borrow under `states_lock.shared`) for pubkey
  resolution; `validator_client.buildPubkeysPerPart(...)` builds the parallel pubkey arrays.
- The heavy `mergeType1ToType2` runs on the chain worker via a thin `chain.mergeBlockProof(...)`
  facade (keeps prover call off libxev; preserves spec layering).
- Lift proposer raw signature into an `xmss.Signature` handle at the call site (single place).

### 5. Block import & verify — `pkgs/state-transition/src/transition.zig`, `chain.zig`

- `verifySignatures` collapses to: structural check (unique AttestationData,
  ≤ `MAX_ATTESTATIONS_DATA`=16) → build `pks_per_message` + `messages` (N atts + proposer last)
  → single `verifyType2`. Delete the per-attestation participant cross-check loop.
- Delete `verifySignaturesParallel` (per-attestation fan-out is gone; Type-2 is one call,
  internally rayon-parallel). `chain.onBlock` calls `verifySignatures` directly.
- `chain.onBlock`: after STF, stamp empty `AttestationData` keys via new
  `forkChoice.stampKnownAttestationDataKey`; delete `storeAggregatedPayload(is_from_block=true)`.
  Then call `deconstructBlockIntoStore` synchronously (no fallback) and, if aggregator, publish.
- Metrics rename: per-attestation verify metrics → per-block `lean_pq_sig_block_proof_*`.

### 6. Deconstruction — new `pkgs/node/src/deconstruct.zig`

`deconstructBlockIntoStore(allocator, fork_choice, pubkey_cache, signed_block, parent_state)
-> DeconstructResult { aggregates: ArrayList(SignedAggregatedAttestation) }`. Direct port of
`_deconstruct_block_into_store` (Section 6.3 algorithm). Runs on the chain worker.

Locking: take `forkChoice.mutex` **shared** to snapshot local partials, release for the heavy
split+aggregate, re-acquire **exclusive** for the map mutation. Retry-once-then-fail on a
rotation race (`error.RaceDuringDeconstruct`) — a strict bound, not a fallback.

Index local partials by `hash_tree_root(AttestationData)` (spec-mandated: equivalent data from
different code paths may not share a Zig map key). Memory: `sszClone` the combined proof into
the map; caller owns the returned aggregates. Metric `lean_block_deconstruct_seconds` +
`lean_block_deconstruct_recovered_bytes`. Publishing via existing `node.publishProducedAggregations`.

### 7. Spectest / hive / serialization

- Bump `leanSpec` submodule to the devnet5 fixture commit (same commit as the runner changes).
- `verify_signatures_runner.zig`: parse `signedBlock.proof` → `verifyType2`; delete
  `parseAggregatedSignatureProof` and the proposer/attestation-signature parsing.
- `ssz_runner.zig`: add `TypeTwoMultiSignature` case; update `SignedBlock` shape; 512 KiB cap.
- `fork_choice_runner.zig`: shared block parser updated to new envelope; exercises deconstruction
  (deferred weight). `networking_codec_runner.zig`: container-binding swaps.
- `pkgs/cli/src/test_driver.zig`: `verify_signatures/run` → Type-2 verify; aggregated-attestation
  gossip `proof` field rename; `AggregatedSignatureProof.init` → `TypeOneMultiSignature.init`.
- `pkgs/network/src/ethlibp2p.zig`, `pkgs/node/src/network.zig`: type-binding swaps only (generic SSZ codec).
- `pkgs/node/src/testing.zig`, `pkgs/database/src/test_helpers.zig`: migrate to Type-1; shared
  `buildSignedBlockProof(...)` test helper for the Type-2 envelope.

Deletion sweep must reach zero: `AggregatedSignatureProof`, `proof_data`, `ByteListMiB`,
`BlockSignatures`, `AttestationSignatures`, `createBlockSignatures`, `signed_block.signature`,
`verifySignaturesParallel`, `verifyAggregatedPayload(Batch)`, `aggregateSignatures`,
`xmss_aggregate`, `xmss_verify_aggregated`, `AggregatedXMSS`, `INV_PROOF_SIZE` (if present).

### 8. Cross-cutting

- **test-config (open risk):** chosen option B (run test-scheme aggregation fixtures). BUT
  `rec_aggregation`'s `test-config` is a crate-level cargo feature (`leansig_wrapper/test-config`)
  that recompiles the whole aggregation bytecode for the test scheme — NOT a lib-level dual
  export like `leansig` (which lets hashsig-glue compile both `hashsig_verify_ssz` and
  `hashsig_test_verify_ssz` in one binary). So prod + test aggregation cannot trivially coexist.
  **Resolution needed before implementation:** either (B1) build `multisig-glue` twice with
  symbol-namespaced wrappers and link both staticlibs, (B2) confirm leanMultisig can lib-level
  dual-export both schemes, or (fallback) revert to skipping test-scheme aggregation fixtures.
  This blocks the build-graph part of the plan; resolve first.
- **Build:** dep-rev bump forces a cold Rust rebuild (CI slow first run). `LOG_INV_RATE_PROD=2`
  stays. Zig 0.16.0 (`ASDF_ZIG_VERSION=0.16.0`).
- **Rollout:** fresh datadir; document in `RELEASE.md`; `lean-quickstart` genesis/config bump at
  release time (out of scope here).

## Test matrix

xmss: Type-1 aggregate→verify; children-only aggregate; Type-2 merge→verify (N msgs);
merge→split_by_msg recovery; verify rejects wrong (hash,slot); proof>512KiB → ProofTooLarge.
types: SSZ round-trip for TypeOne/TypeTwo/SignedBlock/SignedAggAtt.
state-transition: verify happy path; reject duplicate AttestationData; reject >MAX; reject
swapped proposer/att order.
deconstruct: the 10 cases (empty body / fully covered / target≤justified / unseen→as-is /
subset→merge / mixed golden / missing parent state / malformed Type-2 / race-retry-then-fail).
node: onBlock stamps empty keys; block votes count only after next rotation; validator_client
produces a verifiable Type-2 block.
spectest: devnet5 verify_signatures / fork_choice / ssz / networking_codec fixtures.
gate: `just check` grep-clean compile after the deletion sweep.

## Risk register

1. **Type-2 size budget** — add a `MAX_ATTESTATIONS_DATA`-full block smoke test asserting
   encoded Type-2 ≤ 512 KiB before merge.
2. **Deconstruction race** — retry-once-then-fail; unit-tested.
3. **Deconstruction perf on every node** — bounded by target.slot/coverage skips; watch
   `lean_block_deconstruct_seconds` in shadow-testing.
4. **Prover throughput** — production (merge + per-att aggregate) and deconstruction
   (split + aggregate) both on the worker; shadow-test under load before declaring done.
5. **test-config build architecture (8.1)** — must resolve prod/test aggregation coexistence
   before the build-graph work; may force a fallback to skipping test-scheme fixtures.
