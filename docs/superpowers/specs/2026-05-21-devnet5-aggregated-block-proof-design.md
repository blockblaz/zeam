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

### Two independent zeam subsystems (CRITICAL — corrected after codex review)

zeam does NOT compute fork-choice weight from the `latest_*_aggregated_payloads` maps.
There are two separate subsystems, fed by two separate inputs, guarded by two separate locks:

| Subsystem | Source of truth | Fed by | Lock | Purpose |
|---|---|---|---|---|
| Fork-choice weight | `AttestationTracker` (`self.attestations`, per-validator `latestNew`/`latestKnown`) | `onAttestationUnlocked(att, is_from_block)` using `aggregation_bits` | `mutex` (RwLock) | LMD-GHOST head weight |
| Proof pool | `latest_*_aggregated_payloads` (Type-1 proofs) | `storeAggregatedPayload` / deconstruction | `signatures_mutex` | block building + signature re-aggregation + gossip |

`onAttestationUnlocked(is_from_block=true)` writes `latestKnown` directly (forkchoice.zig:1670);
`is_from_block=false` writes `latestNew` (forkchoice.zig:1697). The payload maps never feed the
tracker. So **fork-choice weight needs no proof — only the trusted `aggregation_bits`.**

This is the zeam-vs-leanSpec architectural difference (already noted in project memory). leanSpec's
fork choice reads the payload maps, which is why leanSpec defers block-vote weight until proofs are
recovered. zeam reads the tracker, so **block votes get weight eagerly and there is no deferral.**

### Block import data flow (corrected, no fallback)

```
on_block:
  decode SignedBlock (SSZ)
  SSZ-decode SignedBlock.proof → TypeTwoMultiSignature container (inner .proof = raw type2 wire)
  verify_signatures: single verify_type_2 over all attestations + proposer
                     (FFI consumes the INNER raw type2 wire, NOT the SSZ-framed bytes — see §2.y)
                     + reject malformed/duplicate/out-of-range aggregation_bits (see §5.1)
  state_transition
  # ORDER MATTERS (codex P1, two rounds): the per-validator tracker loop AND the
  # protoarray insert (forkChoice.onBlock at chain.zig:3362) are BOTH fork-choice
  # mutations, and the insert happens FIRST. So the fallible/hard-reject part of
  # deconstruction must complete BEFORE forkChoice.onBlock — otherwise a deconstruction
  # error rejects a block that is already in protoarray + tracker. Use compute/commit:
  #
  # (B1) Deconstruction COMPUTE — fallible, hard error → whole-block reject.
  #      Runs BEFORE forkChoice.onBlock. Produces staged combined Type-1s in memory.
  #      Reads payload pool (snapshot under signatures_mutex) + justified checkpoint; no
  #      fork-choice mutation yet.
  deconstruct_compute:
     for each att where target.slot > justified.slot AND block_participants ⊄ local_union:
        split_type_2_by_msg(inner type2 wire, ...) → Type-1 component; restore participants from att bits
        # Greedy select against ACCUMULATED coverage (codex P2 rounds 3+4) — a validator
        # must not appear in two children of one aggregate_type_1 call. Disjoint-from-block
        # alone is insufficient (two local partials can overlap each other).
        covered = block_participants
        selected = []
        for partial in local partials (by hash_tree_root):
            if partial.validators ⊄ covered: selected += partial; covered |= partial.validators
        if selected non-empty: aggregate_type_1(component + selected) → combined
        else: combined = component
        stage (combined, superseded=selected) for commit
  forkChoice.onBlock(block, post_state)        # protoarray insert (first fc mutation)
  # (C) Fork-choice weight — EAGER, unchanged from devnet4. Uses trusted bits, no proof.
  for each body attestation, for each validator in aggregation_bits:
        onAttestationUnlocked(att_for_validator, is_from_block=true)   → latestKnown
  # (B2) Deconstruction COMMIT — infallible. Only reached once all hard-reject steps passed.
  commit staged proofs → latest_new_aggregated_payloads (under signatures_mutex); drop superseded
  update_head
  # (D) Publishing happens at the node layer (which owns the BeamNode pointer), NOT in
  #     chain.onBlock (BeamChain has no node field — codex P2). onBlock returns / surfaces
  #     the staged aggregates; the node layer publishes them when aggregator.
  if aggregator: node publishes recovered aggregates
```

### Key behavioural points

1. **Fork-choice weight is eager (subsystem A).** Block votes hit `latestKnown` at import via the
   existing `onAttestationUnlocked(is_from_block=true)` path, using only the `aggregation_bits`
   (trusted after the Type-2 verify). This is the SAME mechanism devnet4 uses — we keep it. It is
   NOT a fallback; it is the only weight mechanism zeam has. There is no second source of truth.

2. **Proof recovery is for the pool, not weight (subsystem B).** Deconstruction recovers Type-1
   proofs into `latest_new_aggregated_payloads` so the node can (a) reuse them when building its
   next block and (b) gossip them as an aggregator. These proofs rotate `new → known` via the
   existing `acceptNewAttestationsUnlocked` tick — but that rotation is about *proof availability
   for block building*, NOT fork-choice weight. Weight already landed in step (A).

3. **No empty-key stamping.** The earlier draft proposed stamping empty `AttestationData` keys into
   `latest_known_aggregated_payloads` to mirror leanSpec. We drop that — codex flagged it as a trap
   (a third "known-but-no-proof" state that block-building/coverage code would misread). Since zeam
   weight comes from the tracker, the empty stamp serves no purpose here.

4. **Deconstruction cost is amortized** by the `block_participants ⊄ local_union` and
   `target.slot > justified.slot` skips, so `split_type_2_by_msg` (a prover call) only runs for
   attestations carrying genuinely new coverage.

### Unchanged

protoarray + `AttestationTracker` (LMD-GHOST head selection over 3SF justify/finalize),
payload-map keys, gossip subnets, block-production fixed-point loop, `select_greedily`
set-cover, the eager `onAttestationUnlocked(is_from_block=true)` tracker update on block import,
and our `StoredAggregatedPayload` metadata (`source_payload_participants` /
`source_gossip_participants`) which the Python spec doesn't model but our aggregator pipeline needs.

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
- Rename `AggregatedAttestationsResult.attestation_signatures` → `attestation_type1s:
  ArrayList(TypeOneMultiSignature)` (in-memory product of block production; not SSZ). Do NOT
  introduce a separate `BlockProductionProofs` type — reuse the existing result struct with the
  renamed field. (Earlier draft proposed `BlockProductionProofs`; dropped to avoid a two-doc
  contradiction flagged by codex.)
- `SignedAggregatedAttestation.proof: TypeOneMultiSignature` (was `AggregatedSignatureProof`).
- Forkchoice payload maps: inner proof type → `TypeOneMultiSignature`; keep `StoredAggregatedPayload` wrapper.
- `MessageBinding { hash: [32]u8, slot: u32 }` helper for Type-2 verify slices.
- SSZ field order verified to match spec (participants,proof / proof / block,proof / data,proof).

#### 2.x Type-2 canonical ordering (binding — verify, merge, split must agree)

The Type-2 has no `participants` field; the binding from each component to its validators is the
parallel layout. All three operations (`mergeType1ToType2`, `verifyType2`, `splitType2ByMessage`)
MUST use one canonical layout or they will each be "locally correct" yet disagree:

- **Component order:** body attestations in `block.body.attestations` order (index 0..N-1), then the
  proposer component LAST (index N). No reordering, no sorting.
- **Per-component message binding:** attestation `i` → `(hash_tree_root(att[i].data), att[i].data.slot)`;
  proposer → `(hash_tree_root(block), block.slot)`.
- **Per-component pubkeys:** the attestation's `aggregation_bits.to_validator_indices()` in ascending
  validator-index order, mapped to `validators[vid].attestation_pubkey`; proposer →
  `[validators[proposer_index].proposal_pubkey]` (single key, attestation vs proposal key kind matters).
- **Empty/degenerate guards:** an attestation with zero participant bits is invalid (reject at verify).
  Duplicate or out-of-range bits are rejected (see §5.1). The proposer component always has exactly
  one participant.

#### 2.y Two byte layers — SSZ container vs raw prover wire (codex P1 — avoid double-encode bug)

There are TWO distinct byte representations; conflating them breaks verification:

1. **Raw type2 wire** — what `mergeType1ToType2` (Rust `merge_many_type_1` → `compress_without_pubkeys`)
   returns and what `verifyType2`/`splitType2ByMessage` (Rust `verify_type_2`/`split_type_2_by_msg`
   → `decompress_without_pubkeys`) consume. lz4+postcard, NO SSZ framing.
2. **SSZ-framed `TypeTwoMultiSignature` container** — `SignedBlock.proof: ByteList512KiB` holds
   `ssz_encode(TypeTwoMultiSignature{ proof: <raw type2 wire> })`. This adds the SSZ list-offset
   framing (~4 bytes). **This is the leanSpec wire format** (`SignedBlock.proof.data =
   TypeTwoMultiSignature.encode_bytes()`; verify does `TypeTwoMultiSignature.decode_bytes(...)`),
   so zeam MUST match it byte-for-byte for interop.

Rules:
- **Produce:** `raw = mergeType1ToType2(...)` → `container = TypeTwoMultiSignature{proof: ByteList(raw)}`
  → `SignedBlock.proof = ByteList(ssz_encode(container))`.
- **Verify / split:** `container = ssz_decode(TypeTwoMultiSignature, SignedBlock.proof.data)` → pass
  `container.proof` (the RAW wire) to the Zig FFI wrapper. NEVER pass `SignedBlock.proof.data`
  (SSZ-framed) directly to `verifyType2`/`splitType2ByMessage` — the Rust `decompress_without_pubkeys`
  would choke on the offset bytes and a locally-produced block would fail its own verification.
- **Disagreement with codex's remedy:** codex suggested storing the RAW wire directly in
  `SignedBlock.proof`. That removes the +4 SSZ offset and would DIVERGE from leanSpec's wire format,
  breaking interop. We keep the SSZ container (interop) and instead fix the decode path. The Zig FFI
  wrappers take the raw inner wire; the SSZ-decode of the container happens in verifySignatures /
  deconstruction.

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

**Error-code granularity (codex P2).** The `0/-1/-2` protocol cannot distinguish decode failure,
invalid proof, prover-setup failure, panic, or OOM. `-1` is a generic failure; the Rust side logs
the specific cause (via `tracing`) before returning. If debugging proves this too coarse, add a
distinct `-3` (setup failed) and `-4` (decode failed) later — not required for first cut, but the
wrapper should map `-2`→`ProofTooLarge` and treat any other negative as the operation-specific
`*Failed` error so the distinction can be added without changing call sites.

**Prover-setup failure policy (codex P2 — reconcile with no-fallback).** Today `setupProver`
returns `error.ProverSetupFailed` and callers log + skip aggregation (aggregation.zig:87). That
skip-on-setup-failure behavior is a fallback and conflicts with devnet5's no-fallback rule for the
import path. New policy:
- **Verify path** (`verifyType2`, block import): setup failure is a HARD error — propagate, fail
  the block import. A node that cannot run the verifier cannot safely import blocks.
- **Production path** (`aggregateType1`/`mergeType1ToType2`, block building): setup failure is a
  HARD error — fail block production for this slot (the node simply doesn't propose). This is not a
  silent skip; it surfaces and is logged at error level.
- The `OnceLock<bool>` setup cache stays (idempotent init), but a cached `false` now propagates as a
  hard error to the caller instead of being absorbed.

### 4. Block production — `pkgs/node/src/chain.zig`, `validator_client.zig`

- `produceBlock` returns `{ block, blockRoot, attestation_type1s: ArrayList(TypeOneMultiSignature),
  post_state }` — per-attestation Type-1s, no merge. Mirrors `produce_block_with_signatures`.
- `validator_client._sign_block` equivalent: sign block root (proposal key) → wrap as singleton
  Type-1 → `raw = mergeType1ToType2([*attestation_type1s, proposer_type1], pks_per_part)` →
  `SignedBlock.proof = ssz_encode(TypeTwoMultiSignature{proof: raw})` (§2.y layering — wrap the raw
  wire in the SSZ container, do NOT store raw). Proposer entry **last**.
- Pubkey resolution must NOT hold the state lock across the heavy merge (codex P2), and the resolver
  needs the BLOCK LAYOUT, not just the root (codex P2 round 3 — a state lookup gives validators but
  not the body's `aggregation_bits`/participants/order). Signature:
  `chain.resolveSigningPubkeys(block, attestation_type1s, proposer_index)` — takes the produced block
  (or its participant layout) so it knows exactly which small set to copy. It takes `states_lock.shared`,
  copies out the proposer PROPOSAL pubkey + each attestation component's participant ATTESTATION
  pubkeys (canonical order §2.x; proposer key resolved outside any attestation cache per §5), releases
  the lock, returns owned bytes. The prover `mergeType1ToType2` then runs lock-free. Do NOT hold a
  live `*BeamState` borrow across the merge — that would block block-import waiting on
  `states_lock.exclusive` behind the prover, the exact stall #863 fixed. Do NOT copy all validator
  keys under the lock — only the participant set the block actually references.
- `validator_client.buildPubkeysPerPart(...)` builds the parallel pubkey arrays from those copied
  bytes (lifting to `xmss.PublicKey` handles), in the canonical Type-2 order (§2.x).
- The heavy `mergeType1ToType2` runs on the chain worker via a thin `chain.mergeBlockProof(...)`
  facade (keeps prover call off libxev; preserves spec layering).
- Lift proposer raw signature into an `xmss.Signature` handle at the call site (single place).

### 5. Block import & verify — `pkgs/state-transition/src/transition.zig`, `chain.zig`

- `verifySignatures` collapses to: SSZ-decode `SignedBlock.proof` → `TypeTwoMultiSignature` container
  (§2.y) → structural checks → build `pks_per_message` + `messages` (canonical order §2.x) → single
  `verifyType2(container.proof, ...)` passing the INNER raw wire (not the SSZ-framed bytes).
- **Proposer key must bypass the attestation pubkey cache (codex P1).** `xmss.PublicKeyCache` is
  keyed by validator index and stores ATTESTATION pubkeys. The proposer component (last) needs the
  validator's PROPOSAL pubkey. If a proposer also attested earlier, the cache holds their attestation
  key under the same index → the proposer component would verify with the wrong key → a valid block
  is rejected. Resolve the proposer's proposal pubkey by deserializing it directly (NOT via the
  attestation cache), or via a separate proposal-key cache. Same caveat applies anywhere we resolve
  pubkeys for the proposer component (production §4, deconstruction §6).
- **Structural checks (codex P2 — Type-2 has no `participants`, so `aggregation_bits` is the SOLE
  binding to pubkeys; the old per-attestation participant cross-check is gone, so these must be
  explicit):**
  - unique `AttestationData` across body; count ≤ `MAX_ATTESTATIONS_DATA` (=16).
  - each attestation's `aggregation_bits`: non-empty, no duplicate set bits beyond the bitlist's
    own semantics, every set index `< len(validators)` (reject out-of-range), bitlist length valid.
  - reject if any of these fail BEFORE calling the prover (cheap rejection, avoids a wasted verify).
- Delete `verifySignaturesParallel` (per-attestation fan-out is gone; Type-2 is one call,
  internally rayon-parallel). `chain.onBlock` calls `verifySignatures` directly.
- `chain.onBlock` (corrected — see "Two independent subsystems"; ORDER per codex P1, two rounds —
  the protoarray insert `forkChoice.onBlock` at chain.zig:3362 is the FIRST fork-choice mutation):
  - **(B1) deconstruction COMPUTE** runs BEFORE `forkChoice.onBlock`. Fallible/hard-reject; produces
    staged combined Type-1s in memory; reads the payload pool snapshot + justified checkpoint; makes
    NO fork-choice mutation. Replaces the old `storeAggregatedPayload(is_from_block=true)` loop. No
    empty-key stamping (dropped — point 3).
  - `forkChoice.onBlock` (protoarray insert) → then the eager per-validator
    `onAttestationUnlocked(att, is_from_block=true)` tracker updates (subsystem A — fork-choice weight,
    unchanged from devnet4).
  - **(B2) deconstruction COMMIT** runs after the above succeed: write staged proofs into
    `latest_new_aggregated_payloads` (infallible). A hard-reject in B1 happens before any fork-choice
    mutation, so a rejected block is never left in protoarray/tracker.
  - **Publishing is NOT done inside `chain.onBlock`** (codex P2 — `BeamChain` has no `node` field).
    `onBlock` surfaces the staged aggregates; the node layer that owns the `BeamNode` pointer
    publishes them (see §6).
- **Hard-error policy (codex P2 — specify which current log-and-continue become rejection):**
  - `verifySignatures` failure (structural or crypto) → whole-block REJECT (already the case).
  - deconstruction COMPUTE (B1) failure → whole-block REJECT (new; no fallback). Runs before any
    fork-choice mutation, so a reject leaves protoarray AND tracker untouched.
  - The eager `onAttestationUnlocked(is_from_block=true)` calls: today these can log-and-continue on
    `InvalidAttestation` (unknown head index). Post-`verifySignatures` the bits are trusted, but the
    head block may legitimately be unknown locally (sync gap). Keep log-and-continue HERE
    specifically — an unknown head is a fork-choice availability condition, not a malformed block,
    and rejecting would wrongly drop valid blocks during sync. Document this exception explicitly so
    it isn't mistaken for a swallowed error.
- Metrics rename: per-attestation verify metrics → per-block `lean_pq_sig_block_proof_*`.

### 6. Deconstruction — new `pkgs/node/src/deconstruct.zig`

Split into two functions (codex P1 — compute before fork-choice mutation, commit after):
- `deconstructCompute(allocator, fork_choice, signed_block, parent_state) !StagedDeconstruct` —
  fallible; runs BEFORE `forkChoice.onBlock`. Returns staged combined Type-1s + the partials each
  supersedes. No pool mutation.
- `deconstructCommit(fork_choice, staged) StagedAggregates` — infallible; runs AFTER the fork-choice
  mutations succeed. Writes staged proofs into `latest_new_aggregated_payloads`, drops superseded,
  returns the `SignedAggregatedAttestation` list for the node layer to publish.

Direct port of `_deconstruct_block_into_store` (Section 6.3) but phase-split.

Locking (codex P2 — corrected): the payload maps are guarded by `forkChoice.signatures_mutex`
(NOT the main `forkChoice.mutex`, which guards the protoarray + `AttestationTracker`). COMPUTE takes
`signatures_mutex` only to snapshot local partials, releases it for the heavy split+aggregate prover
calls. COMMIT re-takes `signatures_mutex` and mutates. `SyncMutex` is exclusive (no shared mode), so
snapshot copies out what it needs and drops the lock before the FFI. Do NOT hold the main `mutex`
across the prover calls.

**COMMIT is infallible (codex P2 round 4).** COMMIT runs AFTER the fork-choice mutations
(`forkChoice.onBlock` + tracker), so it must NOT be able to fail — otherwise a failed commit reports
a failed import after fork choice was already mutated, the exact inconsistency the compute/commit
split exists to prevent. The earlier `error.RaceDuringDeconstruct` retry-then-fail is REMOVED. A
rotation race between compute and commit is BENIGN: the combined proof is a superset of the partials
it merged, so (a) inserting it into `latest_new` is always valid, and (b) "remove superseded" is
best-effort — if rotation already moved a partial to `latest_known`, leave it (the greedy set-cover
at block-build/aggregation time dedups the redundant coverage). So COMMIT = idempotent insert +
best-effort remove, returns no error. This is correct concurrency handling for a non-correctness-path
(subsystem B) operation, not an error-masking fallback — fork-choice weight already landed via the
tracker (subsystem A).

Index local partials by `hash_tree_root(AttestationData)` (spec-mandated: equivalent data from
different code paths may not share a Zig map key). Memory: `sszClone` the combined proof into
the map; caller owns the returned aggregates. Metric `lean_block_deconstruct_seconds` +
`lean_block_deconstruct_recovered_bytes`.

**Disjoint selection against accumulated coverage (codex P2 rounds 3+4).** A validator must not
appear in two children of one `aggregate_type_1` call, or the merge can fail / produce an invalid
combined proof. The block-coverage skip (`block_participants ⊄ local_union`) only catches FULL
coverage. A naive "disjoint from the block component" filter is ALSO insufficient: two local partials
can overlap EACH OTHER (block `{A,B}`, local `{C,D}` and `{D,E}` → D twice). So select greedily
against an ACCUMULATED union, exactly like the spec's `select_greedily`: start `covered =
block_participants`; for each local partial, select it only if it adds validators ∉ `covered`, then
`covered |= partial.validators`. This guarantees no validator appears in two selected children. If
nothing adds coverage, `combined = component`. Tests: the `{A}`+`{A,B}` case AND the overlapping-local
`{C,D}`+`{D,E}` case.

**Proposer key resolution (codex P1).** When building `public_keys_per_message` for the split layout,
the proposer component must use the PROPOSAL pubkey, not the attestation-keyed cache (same caveat as
§5). Resolve it directly.

**Publishing path (codex P2).** `deconstructCommit` does NOT publish — `BeamChain` has no
`BeamNode` pointer. It returns the recovered aggregates (`StagedAggregates`). The node
layer (which owns `BeamNode`, e.g. the same place `submitAggregateOnInterval` hands a `BeamNode*` to
the aggregate worker) drains that list to `node.publishProducedAggregations(...)` when this node is
an aggregator. The plan must thread the aggregates from `chain.onBlock`'s caller up to the node
layer, not call `self.node.*` inside chain.

### 7. Spectest / hive / serialization

- Bump `leanSpec` submodule to the devnet5 fixture commit (same commit as the runner changes).
- `verify_signatures_runner.zig`: parse `signedBlock.proof` → `verifyType2`; delete
  `parseAggregatedSignatureProof` and the proposer/attestation-signature parsing.
- `ssz_runner.zig`: add `TypeTwoMultiSignature` case; update `SignedBlock` shape; 512 KiB cap.
- `fork_choice_runner.zig`: shared block parser updated to new envelope. Watch for fixtures that
  assert head weight from block-imported votes — zeam applies that weight eagerly via the tracker
  (subsystem A), so zeam may credit weight a tick earlier than a payload-map-based reference. If a
  devnet5 fixture encodes leanSpec's deferred-weight timing, document the divergence; it is a local
  fork-choice timing difference, not a consensus rule. `networking_codec_runner.zig`: container-binding swaps.
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
  **Resolution needed before implementation (resolve FIRST — codex P2):**
  - **(B1) two-build link.** Enabling the `test-config` cargo feature only produces ONE
    `multisig-glue` variant. B1 requires building the crate TWICE (prod + `test-config`),
    each exporting symbols namespaced (`xmss_aggregate_type_1` vs `xmss_aggregate_type_1_test`),
    then wiring BOTH into `zeam-glue` and `build.zig` so the final binary links both bytecodes.
    Zig dispatches by `leanEnv` to the right symbol (mirror hashsig.zig `verifySsz`/`verifySszTest`).
    Just flipping a feature flag is insufficient and will either call the wrong scheme or fail to link.
  - **(B2) lib-level dual-export.** Confirm whether `anshalshukla/leanMultisig@devnet5-patched`
    exposes both schemes at the lib level (like `leansig` does for hashsig). If so, one build
    exports both — far simpler than B1.
  - **(A-fallback)** if neither is feasible without major effort, revert to skipping test-scheme
    aggregation fixtures (devnet4 status quo) and keep the `verify_signatures_runner` skip.
  This blocks the build-graph part of the plan; it is Task 0 in the implementation plan.
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
deconstruct: empty body / fully covered / target≤justified / unseen→as-is / subset→merge /
partial-overlap {A}+{A,B}→no-double-count / mixed golden / missing parent state / malformed Type-2 /
race-retry-then-fail.
node: onBlock applies eager tracker weight (block votes count at import via
onAttestationUnlocked(is_from_block=true)); deconstruction recovers Type-1 proofs into latest_new;
recovered proofs become available for block building after the next rotation tick; validator_client
produces a verifiable Type-2 block.
spectest: devnet5 verify_signatures / fork_choice / ssz / networking_codec fixtures.
gate: `just check` grep-clean compile after the deletion sweep.

## Risk register

1. **Type-2 size budget** — add a `MAX_ATTESTATIONS_DATA`-full block smoke test asserting
   encoded Type-2 ≤ 512 KiB before merge.
2. **Deconstruction race** — commit is infallible (idempotent insert + best-effort remove); benign
   rotation race between compute and commit handled without error; unit-tested.
3. **Deconstruction perf on every node** — bounded by target.slot/coverage skips; watch
   `lean_block_deconstruct_seconds` in shadow-testing.
4. **Prover throughput** — production (merge + per-att aggregate) and deconstruction
   (split + aggregate) both on the worker; shadow-test under load before declaring done.
5. **test-config build architecture (8.1)** — must resolve prod/test aggregation coexistence
   before the build-graph work; may force a fallback to skipping test-scheme fixtures.
