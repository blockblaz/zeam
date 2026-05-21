# Devnet 5 — Aggregated Block Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port leanSpec PR #717 to zeam — collapse per-attestation proofs + proposer signature into a single Type-2 aggregated block proof on `SignedBlock.proof`.

**Architecture:** Two proof shapes — Type-1 (many validators, one message) and Type-2 (merge of N Type-1s over distinct messages). Blocks carry one Type-2 blob. Block import verifies it whole, defers per-attestation proof recovery to a deconstruction step that feeds the existing `latest_new → rotation → latest_known` pipeline. Hard cutover, no back-compat.

**Tech Stack:** Zig 0.16.0 (`ASDF_ZIG_VERSION=0.16.0`), Rust FFI (`rust/multisig-glue` → `anshalshukla/leanMultisig@devnet5-patched` rev `f33a0775`), SSZ, leanMultisig zk prover.

**Design doc:** `docs/superpowers/specs/2026-05-21-devnet5-aggregated-block-proof-design.md`

**Commands:**
- Build: `ASDF_ZIG_VERSION=0.16.0 zig build`
- Unit tests: `ASDF_ZIG_VERSION=0.16.0 zig build test`
- Single-package test: `ASDF_ZIG_VERSION=0.16.0 zig build test -- <filter>` (confirm filter syntax during Task 0)
- Spectest: `ASDF_ZIG_VERSION=0.16.0 zig build spectest`

**Conventions for this plan:**
- "Read first" steps are real actions (the executor must see current code before editing a large existing file); they are not placeholders.
- Zig has no per-function test runner like pytest; tests are `test "name" {}` blocks compiled into the package test binary. "Run it to verify it fails" means the test binary fails to compile or the assertion fails.

**Commit & pre-commit convention (overrides every inline `git commit` example below — per AGENTS.md, codex P3):**
- The inline commit examples use shorthand like `feat(...)`. IGNORE that prefix style. AGENTS.md requires `<package(s)>: description` (lowercase, comma-separated packages, no `feat`/`chore`). E.g. `xmss, multisig-glue: Type-1/Type-2 FFI surface`, `node: deconstruct block Type-2 into proof pool`.
- Before EVERY commit, run the full AGENTS.md pre-commit checklist and ensure it passes:
  - `cargo fmt --manifest-path rust/Cargo.toml --all -- --check`
  - `cargo clippy --manifest-path rust/Cargo.toml --workspace -- -D warnings`
  - `zig fmt --check .`
  - `ASDF_ZIG_VERSION=0.16.0 zig build test --summary all`
  - `ASDF_ZIG_VERSION=0.16.0 zig build simtest --summary all`
- Do not commit if any check fails. Fix first. (The per-task "run the test" steps are the fast inner loop; the full checklist is the commit gate.)
- Keep changes minimal and focused per AGENTS.md — no unrelated refactors bundled in.

---

## Phase 0 — Gating investigation (blocks build graph)

### Task 0: Resolve test-config aggregation build architecture

**Why first:** `rec_aggregation`'s `test-config` is a crate-level cargo feature (recompiles bytecode for the test scheme), not a lib-level dual export. Whether prod+test aggregation can coexist in one binary determines the entire build graph for Phases 1 and 7. Decision §8.1 was "consistent with spec" (run test-scheme fixtures) but it is conditioned on this being feasible.

**Files:**
- Read: `rust/hashsig-glue/src/lib.rs:558-610` (how dual scheme works today)
- Read: `rust/multisig-glue/Cargo.toml`, `rust/zeam-glue/src/lib.rs`, `build.zig:44-79`
- Investigate (remote): `anshalshukla/leanMultisig@devnet5-patched` `leansig_wrapper` and `rec_aggregation` — does the bytecode/scheme switch on a compile-time const or a runtime parameter?

- [ ] **Step 1: Determine coexistence feasibility**

Answer concretely (write findings into the design doc's §8 open-risk section):
- Does `aggregate_type_1` / `verify_type_2` take the scheme as a runtime parameter, or is it baked at compile time via `leansig_wrapper/test-config`?
- Can both the prod and test aggregation bytecode be linked into one binary with distinct symbols?

- [ ] **Step 2: Pick the build path and record it**

Decide one of:
- **(B1)** Two `multisig-glue` builds with symbol-namespaced wrappers (`xmss_*` prod, `xmss_*_test`), both linked through `zeam-glue`.
- **(B2)** leanMultisig dual-export confirmed → single build exposes both, mirror hashsig's `mod test_scheme`.
- **(A-fallback)** Coexistence infeasible without major effort → keep skipping test-scheme aggregation fixtures (devnet4 status quo); update §8.1 decision and the `verify_signatures_runner` skip stays.

- [ ] **Step 3: Commit the decision**

```bash
git add docs/superpowers/specs/2026-05-21-devnet5-aggregated-block-proof-design.md
git commit -m "docs: resolve devnet5 test-config aggregation build path"
```

**Gate:** Phases 1 and 7's build-graph steps assume the path chosen here. If (A-fallback), all "test-scheme" sub-steps in Task 13 and Task 23 are skipped.

---

## Phase 1 — Rust FFI + Zig xmss wrappers

### Task 1: Bump leanMultisig dependency

**Files:**
- Modify: `rust/multisig-glue/Cargo.toml`

- [ ] **Step 1: Pin the devnet5 rev**

Replace the three git deps' `rev` with `f33a0775e4f88ec8b23b2cb8282a4472c145fb93`:

```toml
[dependencies]
rec_aggregation = { git = "https://github.com/anshalshukla/leanMultisig.git", rev = "f33a0775e4f88ec8b23b2cb8282a4472c145fb93" }
leansig_wrapper = { git = "https://github.com/anshalshukla/leanMultisig.git", rev = "f33a0775e4f88ec8b23b2cb8282a4472c145fb93" }
backend          = { git = "https://github.com/anshalshukla/leanMultisig.git", rev = "f33a0775e4f88ec8b23b2cb8282a4472c145fb93" }
rayon = "1"
```

**If Task 0 chose (B1) — dual-build (codex P2):** a cargo feature alone builds only ONE variant; B1 needs BOTH prod and test bytecode in the final binary. That requires more than a feature line:
- Add `[features] test-config = ["rec_aggregation/test-config", "leansig_wrapper/test-config"]` to `multisig-glue/Cargo.toml`.
- Build `multisig-glue` TWICE in `build.zig` (one default, one with `--features test-config`), producing two distinct staticlibs/object sets.
- Namespace the test build's exported symbols (`xmss_aggregate_type_1_test`, `xmss_verify_type_2_test`, …) so they don't collide with the prod symbols — either via a cfg-gated `#[no_mangle]` name in `lib.rs` (`#[cfg_attr(feature="test-config", export_name="..._test")]`) or a separate wrapper crate.
- Wire BOTH symbol sets through `rust/zeam-glue` and link both in `build.zig:44-79`.
- Zig side (Task 3) dispatches by `leanEnv` to prod vs `_test` symbols, mirroring `hashsig.zig` `verifySsz`/`verifySszTest`.
If Task 0 chose (B2) lib-level dual-export: skip the double build; expose both schemes from one build. If (A-fallback): no test-scheme symbols at all; the `verify_signatures_runner` skip stays (Task 13).

- [ ] **Step 2: Verify the new API surface resolves**

Run: `cd rust && cargo build -p multisig-glue 2>&1 | head -40`
Expected: compile errors ONLY about the old `xmss_aggregate`/`AggregatedXMSS` symbols we're about to replace (confirms the new crate version is fetched). If it errors on a missing git rev, fix the rev.

- [ ] **Step 3: Commit**

```bash
git add rust/multisig-glue/Cargo.toml rust/Cargo.lock
git commit -m "build(multisig-glue): bump leanMultisig to devnet5-patched f33a0775"
```

### Task 2: Rewrite the FFI surface (prod scheme)

**Files:**
- Modify: `rust/multisig-glue/src/lib.rs` (replace aggregate/verify functions; keep setup_prover/verifier/rayon)
- Modify: `rust/zeam-glue/src/lib.rs` (re-export new symbols)

- [ ] **Step 1: Add the private decompress helpers**

In `lib.rs`, after the `PublicKey`/`Signature` repr(C) structs:

```rust
use rec_aggregation::{
    TypeOneMultiSignature, TypeTwoMultiSignature,
    aggregate_type_1, verify_type_1, merge_many_type_1,
    split_type_2_by_msg, verify_type_2, init_aggregation_bytecode,
};
use leansig_wrapper::{XmssPublicKey, XmssSignature};

fn type_1_decompress(bytes: &[u8], pubkeys: Vec<XmssPublicKey>) -> Option<TypeOneMultiSignature> {
    TypeOneMultiSignature::decompress_without_pubkeys(bytes, pubkeys)
}
fn type_2_decompress(bytes: &[u8], pubkeys_per_info: Vec<Vec<XmssPublicKey>>) -> Option<TypeTwoMultiSignature> {
    TypeTwoMultiSignature::decompress_without_pubkeys(bytes, pubkeys_per_info)
}

// Copy `src` into the caller buffer; return the 0/-1/-2 protocol code.
unsafe fn write_out(src: &[u8], out_buf: *mut u8, out_cap: usize, out_written: *mut usize) -> i32 {
    *out_written = src.len();
    if src.len() > out_cap { return -2; }
    std::ptr::copy_nonoverlapping(src.as_ptr(), out_buf, src.len());
    0
}
```

- [ ] **Step 2: Implement `xmss_aggregate_type_1`**

```rust
#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_type_1(
    raw_pub_keys: *const *const PublicKey,
    raw_signatures: *const *const Signature,
    num_raw: usize,
    num_children: usize,
    child_all_pub_keys: *const *const PublicKey,
    child_num_keys: *const usize,
    child_proof_ptrs: *const *const u8,
    child_proof_lens: *const usize,
    message_hash_ptr: *const u8,
    slot: u32,
    log_inv_rate: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    if message_hash_ptr.is_null() || out_written.is_null() { return -1; }
    let message: [u8; 32] = match slice::from_raw_parts(message_hash_ptr, 32).try_into() {
        Ok(a) => a, Err(_) => return -1,
    };

    // raw (pk, sig) pairs
    let mut raw_xmss: Vec<(XmssPublicKey, XmssSignature)> = Vec::with_capacity(num_raw);
    if num_raw > 0 {
        let pks = slice::from_raw_parts(raw_pub_keys, num_raw);
        let sigs = slice::from_raw_parts(raw_signatures, num_raw);
        for i in 0..num_raw {
            if pks[i].is_null() || sigs[i].is_null() { return -1; }
            raw_xmss.push(((*pks[i]).inner.clone(), (*sigs[i]).inner.clone()));
        }
    }

    // children: Vec<TypeOneMultiSignature> reconstructed from (pubkeys, wire bytes)
    let mut children: Vec<TypeOneMultiSignature> = Vec::with_capacity(num_children);
    if num_children > 0 {
        let counts = slice::from_raw_parts(child_num_keys, num_children);
        let proof_ptrs = slice::from_raw_parts(child_proof_ptrs, num_children);
        let proof_lens = slice::from_raw_parts(child_proof_lens, num_children);
        let total: usize = counts.iter().sum();
        let all_pks = slice::from_raw_parts(child_all_pub_keys, total);
        let mut off = 0usize;
        for i in 0..num_children {
            let n = counts[i];
            let mut pks = Vec::with_capacity(n);
            for j in 0..n {
                if all_pks[off + j].is_null() { return -1; }
                pks.push((*all_pks[off + j]).inner.clone());
            }
            off += n;
            if proof_ptrs[i].is_null() || proof_lens[i] == 0 { return -1; }
            let wire = slice::from_raw_parts(proof_ptrs[i], proof_lens[i]);
            match type_1_decompress(wire, pks) {
                Some(t1) => children.push(t1),
                None => return -1,
            }
        }
    }

    let children_opt = if children.is_empty() { None } else { Some(children) };
    let t1 = match aggregate_type_1(raw_xmss, children_opt, message, slot, log_inv_rate) {
        Ok(t1) => t1, Err(_) => return -1,
    };
    write_out(&t1.compress_without_pubkeys(), out_buf, out_cap, out_written)
}
```

> NOTE: the exact `aggregate_type_1` Rust signature (arg order, `Result` vs panic, whether children is `Option`) must be confirmed against `rec_aggregation` at rev `f33a0775` while implementing — adjust the call accordingly. The leanMultisig-py wrapper at v0.0.5 is the reference for arg shapes.

- [ ] **Step 3: Implement `xmss_verify_type_1`**

```rust
#[no_mangle]
pub unsafe extern "C" fn xmss_verify_type_1(
    public_keys: *const *const PublicKey,
    num_keys: usize,
    message_hash_ptr: *const u8,
    slot: u32,
    type_1_bytes: *const u8,
    type_1_len: usize,
) -> bool {
    if message_hash_ptr.is_null() || type_1_bytes.is_null() { return false; }
    let message: [u8; 32] = match slice::from_raw_parts(message_hash_ptr, 32).try_into() {
        Ok(a) => a, Err(_) => return false,
    };
    let pk_ptrs = slice::from_raw_parts(public_keys, num_keys);
    let mut pks = Vec::with_capacity(num_keys);
    for &p in pk_ptrs { if p.is_null() { return false; } pks.push((*p).inner.clone()); }
    let wire = slice::from_raw_parts(type_1_bytes, type_1_len);
    let t1 = match type_1_decompress(wire, pks) { Some(t) => t, None => return false };
    verify_type_1(&t1).is_ok() && t1.info.without_pubkeys.message == message
        && t1.info.without_pubkeys.slot == slot
}
```

> Confirm whether `verify_type_1` itself checks (message, slot) or whether the wrapper must compare — adjust to avoid double/under-checking.

- [ ] **Step 4: Implement `xmss_merge_type_1_to_type_2`**

```rust
#[no_mangle]
pub unsafe extern "C" fn xmss_merge_type_1_to_type_2(
    num_parts: usize,
    type_1_proof_ptrs: *const *const u8,
    type_1_proof_lens: *const usize,
    pks_flat: *const *const PublicKey,
    pks_per_part_counts: *const usize,
    log_inv_rate: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    if num_parts == 0 || out_written.is_null() { return -1; }
    let proof_ptrs = slice::from_raw_parts(type_1_proof_ptrs, num_parts);
    let proof_lens = slice::from_raw_parts(type_1_proof_lens, num_parts);
    let counts = slice::from_raw_parts(pks_per_part_counts, num_parts);
    let total: usize = counts.iter().sum();
    let all_pks = slice::from_raw_parts(pks_flat, total);
    let mut parts: Vec<TypeOneMultiSignature> = Vec::with_capacity(num_parts);
    let mut off = 0usize;
    for i in 0..num_parts {
        let n = counts[i];
        let mut pks = Vec::with_capacity(n);
        for j in 0..n { if all_pks[off+j].is_null() { return -1; } pks.push((*all_pks[off+j]).inner.clone()); }
        off += n;
        if proof_ptrs[i].is_null() || proof_lens[i] == 0 { return -1; }
        let wire = slice::from_raw_parts(proof_ptrs[i], proof_lens[i]);
        match type_1_decompress(wire, pks) { Some(t) => parts.push(t), None => return -1 }
    }
    let t2 = match merge_many_type_1(parts, log_inv_rate) { Ok(t) => t, Err(_) => return -1 };
    write_out(&t2.compress_without_pubkeys(), out_buf, out_cap, out_written)
}
```

- [ ] **Step 5: Implement `xmss_split_type_2_by_msg`**

```rust
#[no_mangle]
pub unsafe extern "C" fn xmss_split_type_2_by_msg(
    type_2_bytes: *const u8,
    type_2_len: usize,
    pks_flat: *const *const PublicKey,
    pks_per_message_counts: *const usize,
    num_messages: usize,
    target_message_hash: *const u8,
    log_inv_rate: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    if type_2_bytes.is_null() || target_message_hash.is_null() || out_written.is_null() { return -1; }
    let target: [u8; 32] = match slice::from_raw_parts(target_message_hash, 32).try_into() {
        Ok(a) => a, Err(_) => return -1,
    };
    let counts = slice::from_raw_parts(pks_per_message_counts, num_messages);
    let total: usize = counts.iter().sum();
    let all_pks = slice::from_raw_parts(pks_flat, total);
    let mut per_msg: Vec<Vec<XmssPublicKey>> = Vec::with_capacity(num_messages);
    let mut off = 0usize;
    for i in 0..num_messages {
        let n = counts[i];
        let mut pks = Vec::with_capacity(n);
        for j in 0..n { if all_pks[off+j].is_null() { return -1; } pks.push((*all_pks[off+j]).inner.clone()); }
        off += n; per_msg.push(pks);
    }
    let wire = slice::from_raw_parts(type_2_bytes, type_2_len);
    let t2 = match type_2_decompress(wire, per_msg) { Some(t) => t, None => return -1 };
    let t1 = match split_type_2_by_msg(&t2, &target, log_inv_rate) { Ok(t) => t, Err(_) => return -1 };
    write_out(&t1.compress_without_pubkeys(), out_buf, out_cap, out_written)
}
```

> Confirm `split_type_2_by_msg` arg shape (does it take the full per-message layout or rederive from t2.info?). Adjust.

- [ ] **Step 6: Implement `xmss_verify_type_2` and `xmss_verify_type_1_batch`**

```rust
#[no_mangle]
pub unsafe extern "C" fn xmss_verify_type_2(
    type_2_bytes: *const u8,
    type_2_len: usize,
    pks_flat: *const *const PublicKey,
    pks_per_message_counts: *const usize,
    num_messages: usize,
    message_hashes: *const u8,   // num_messages * 32
    message_slots: *const u32,   // num_messages
) -> bool {
    if type_2_bytes.is_null() || message_hashes.is_null() || message_slots.is_null() { return false; }
    let counts = slice::from_raw_parts(pks_per_message_counts, num_messages);
    let total: usize = counts.iter().sum();
    let all_pks = slice::from_raw_parts(pks_flat, total);
    let mut per_msg: Vec<Vec<XmssPublicKey>> = Vec::with_capacity(num_messages);
    let mut off = 0usize;
    for i in 0..num_messages {
        let n = counts[i];
        let mut pks = Vec::with_capacity(n);
        for j in 0..n { if all_pks[off+j].is_null() { return false; } pks.push((*all_pks[off+j]).inner.clone()); }
        off += n; per_msg.push(pks);
    }
    let hashes = slice::from_raw_parts(message_hashes, num_messages * 32);
    let slots = slice::from_raw_parts(message_slots, num_messages);
    let messages: Vec<([u8;32], u32)> = (0..num_messages).map(|i| {
        let mut h = [0u8;32]; h.copy_from_slice(&hashes[i*32..i*32+32]); (h, slots[i])
    }).collect();
    let wire = slice::from_raw_parts(type_2_bytes, type_2_len);
    let t2 = match type_2_decompress(wire, per_msg) { Some(t) => t, None => return false };
    verify_type_2(&t2, &messages).is_ok()
}
```

`xmss_verify_type_1_batch`: same per-task decode loop as today's `xmss_verify_aggregated_batch` (transition.zig pattern), calling `verify_type_1` per task on the rayon pool. Confirm `verify_type_2`'s exact message-binding arg shape against the crate.

- [ ] **Step 7: Delete old symbols and re-export new ones**

Delete `xmss_aggregate`, `xmss_verify_aggregated`, `xmss_verify_aggregated_batch`, `xmss_aggregate_signature_to_bytes`, `xmss_aggregate_signature_from_bytes`, `xmss_free_aggregate_signature`, `AggregatedXMSS` usages. In `rust/zeam-glue/src/lib.rs` swap the re-export list to the six new symbols.

- [ ] **Step 8: Build the Rust glue**

Run: `cd rust && cargo build -p multisig-glue -p zeam-glue 2>&1 | tail -20`
Expected: clean build.

- [ ] **Step 9: Commit**

```bash
git add rust/multisig-glue/src/lib.rs rust/zeam-glue/src/lib.rs
git commit -m "feat(multisig-glue): Type-1/Type-2 bytes-in/out FFI surface"
```

### Task 3: Zig xmss wrappers + ByteList512KiB

**Files:**
- Modify: `pkgs/xmss/src/aggregation.zig`
- Modify: `pkgs/xmss/src/lib.zig` (re-exports)
- Test: in-file `test "..."` blocks in `aggregation.zig`

- [ ] **Step 1: Write failing round-trip test**

Add to `aggregation.zig` (prod scheme; uses real phony keys helper already present in the file's existing tests — read the existing test setup first to reuse `xmss.PublicKey`/`Signature` fixtures):

```zig
test "Type-1 aggregate then verify round-trips" {
    const allocator = std.testing.allocator;
    // build raw (pk, sig) for one validator over a fixed message+slot,
    // aggregate into a Type-1, then verify with the same pk.
    // (reuse the phony-signature helper used by existing aggregateSignatures tests)
    // EXPECT: verifyType1 succeeds; verify with a different message fails.
}
```

- [ ] **Step 2: Run, expect compile failure** (symbols `aggregateType1`/`verifyType1`/`ByteList512KiB` undefined)

Run: `ASDF_ZIG_VERSION=0.16.0 zig build test 2>&1 | head -20`
Expected: FAIL — undefined `ByteList512KiB` / `aggregateType1`.

- [ ] **Step 3: Add constant + extern decls + wrappers**

Replace `MAX_AGGREGATE_SIGNATURE_SIZE`/`ByteListMiB` with:
```zig
pub const MAX_AGGREGATE_PROOF_SIZE: usize = 512 * 1024;
pub const ByteList512KiB = ssz.utils.List(u8, MAX_AGGREGATE_PROOF_SIZE);
pub const MessageBinding = struct { hash: [32]u8, slot: u32 };
```
Add `extern fn` decls matching Task 2's six symbols. Implement `aggregateType1`, `verifyType1`, `verifyType1Batch`, `mergeType1ToType2`, `splitType2ByMessage`, `verifyType2` per design §3.4. Each output wrapper: call into a stack `[MAX_AGGREGATE_PROOF_SIZE]u8` buffer, handle return codes (`-2` → `error.ProofTooLarge`, `-1` → the matching `error.*Failed`), then append bytes into the `*ByteList512KiB` out-param. Add the new `AggregationError` variants. Delete `aggregateSignatures`, `verifyAggregatedPayload`, `verifyAggregatedPayloadBatch`, `AggregatedPayloadVerifyBatch`, and the old extern decls.

- [ ] **Step 4: Run round-trip test, expect pass**

Run: `ASDF_ZIG_VERSION=0.16.0 zig build test 2>&1 | tail -20`
Expected: PASS (prod scheme available; if the prover bytecode isn't present in the test env the existing tests already gate on that — match their skip pattern).

- [ ] **Step 5: Add Type-2 merge/split/verify tests**

```zig
test "Type-2 merge of two Type-1s verifies with both message bindings" { ... }
test "Type-2 split_by_msg recovers a component verifiable as Type-1" { ... }
test "verifyType2 rejects a wrong (hash, slot) binding" { ... }
```

- [ ] **Step 6: Run, expect pass; then commit**

```bash
git add pkgs/xmss/src/aggregation.zig pkgs/xmss/src/lib.zig
git commit -m "feat(xmss): Type-1/Type-2 Zig wrappers + ByteList512KiB"
```

---

## Phase 2 — Types

### Task 4: `TypeOneMultiSignature` + `TypeTwoMultiSignature`

**Files:**
- Modify: `pkgs/types/src/aggregation.zig`
- Modify: `pkgs/types/src/lib.zig` (re-exports)
- Test: in-file tests

- [ ] **Step 1: Write failing SSZ round-trip test for both types**

```zig
test "TypeOneMultiSignature SSZ round-trips" { ... build, serialize, deserialize, expectEqual ... }
test "TypeTwoMultiSignature SSZ round-trips" { ... }
```

- [ ] **Step 2: Run, expect failure** (types undefined). `ASDF_ZIG_VERSION=0.16.0 zig build test`.

- [ ] **Step 3: Rename `AggregatedSignatureProof` → `TypeOneMultiSignature`**

Field `proof_data: ByteListMiB` → `proof: ByteList512KiB`. Update `init/deinit/toJson/toJsonString`. Rewrite `aggregate` to call `xmss.aggregateType1` (children as `[]const struct{proof,pks}` per §2.2), `verify` to call `xmss.verifyType1`. Keep `selectGreedily` (it's the existing greedy plumbing). Add `TypeTwoMultiSignature { proof: ByteList512KiB }` with `init/deinit/aggregate(parts, pks_per_part)/verify(pks_per_message, messages)/splitByMessage(...)/toJson`. Update `lib.zig` re-exports: remove `AggregatedSignatureProof`, add both new names + `MessageBinding`.

- [ ] **Step 4: Run, expect pass. Commit.**

```bash
git add pkgs/types/src/aggregation.zig pkgs/types/src/lib.zig
git commit -m "feat(types): TypeOneMultiSignature + TypeTwoMultiSignature"
```

### Task 5: `SignedBlock` envelope + delete BlockSignatures/AttestationSignatures

**Files:**
- Modify: `pkgs/types/src/block.zig`
- Test: in-file

- [ ] **Step 1: Failing test — SignedBlock with single proof round-trips**

```zig
test "SignedBlock { block, proof } SSZ round-trips" { ... }
```

- [ ] **Step 2: Run, expect failure** (SignedBlock still has `.signature`).

- [ ] **Step 3: Apply the surgery**

`SignedBlock { block: BeamBlock, proof: aggregation.ByteList512KiB }` with updated `deinit/toJson` (proof as hex). DELETE `BlockSignatures`, `AttestationSignatures` (the `ssz.utils.List(...)` const at `block.zig:20`), and `createBlockSignatures` — do NOT "update" the `AttestationSignatures` const, remove it entirely (the deletion sweep in Task 15 expects zero references; codex P2). Rename `AggregatedAttestationsResult.attestation_signatures` field to `attestation_type1s: std.ArrayList(TypeOneMultiSignature)` — use this name everywhere (Tasks 7/8 depend on it; do NOT introduce a separate `BlockProductionProofs` type). Migrate `AggregateInnerMap` (block.zig:140) to produce a `TypeOneMultiSignature` via `aggregateType1`.

- [ ] **Step 4: Run, expect pass. Commit.**

```bash
git add pkgs/types/src/block.zig
git commit -m "feat(types): SignedBlock single Type-2 proof envelope"
```

### Task 6: `SignedAggregatedAttestation.proof` + forkchoice payload type

**Files:**
- Modify: `pkgs/types/src/attestation.zig` (SignedAggregatedAttestation)
- Modify: `pkgs/node/src/forkchoice.zig` (StoredAggregatedPayload.proof type, AggregatedPayloadsMap)
- Modify: `pkgs/types/src/block.zig` (StoredAggregatedPayload if defined there)

- [ ] **Step 1: Change the field types**

`SignedAggregatedAttestation.proof: TypeOneMultiSignature`. `StoredAggregatedPayload.proof: TypeOneMultiSignature` (keep `slot`, `source_payload_participants`, `source_gossip_participants`). No behavioral change — pure type swap.

- [ ] **Step 2: Build the package**

Run: `ASDF_ZIG_VERSION=0.16.0 zig build 2>&1 | head -40`
Expected: errors now concentrated in node/state-transition/spectest callsites (Phases 3-5/7), NOT in types. Those are addressed in later tasks. If types itself errors, fix here.

- [ ] **Step 3: Commit**

```bash
git add pkgs/types/src/attestation.zig pkgs/node/src/forkchoice.zig pkgs/types/src/block.zig
git commit -m "feat(types): SignedAggregatedAttestation + payload map use TypeOneMultiSignature"
```

---

## Phase 3 — verify_signatures + block import

### Task 7: Rewrite `verifySignatures` to single Type-2 verify

**Files:**
- Modify: `pkgs/state-transition/src/transition.zig`
- Test: in-file tests in `transition.zig`

- [ ] **Step 1: Failing test — duplicate AttestationData rejected**

```zig
test "verifySignatures rejects duplicate AttestationData in body" {
    // build a SignedBlock whose body has two attestations with identical data;
    // EXPECT error.InvalidBlockSignatures (or a new error.DuplicateAttestationData)
}
```

- [ ] **Step 2: Run, expect failure** (current verifySignatures has no such check; test won't compile against new SignedBlock anyway).

- [ ] **Step 3: Rewrite `verifySignatures`** per design §5.1

**First SSZ-decode the container (codex P1 — §2.y two byte layers):** `container = ssz_decode(TypeTwoMultiSignature, signed_block.proof.data)`. The FFI consumes `container.proof` (raw lz4+postcard wire); NEVER pass `signed_block.proof.data` (SSZ-framed) directly to `xmss.verifyType2` or it chokes on the offset bytes. Add `assertUniqueAndCappedAttestationData` (unique + ≤ `MAX_ATTESTATIONS_DATA`). **Add explicit `aggregation_bits` validation (codex P2 — Type-2 has no `participants` field, so the bits are the SOLE binding to pubkeys; the old per-attestation participant cross-check is gone):** for each attestation reject if bits are empty, any set index ≥ `len(validators)` (out-of-range), or the bitlist length is invalid. Do these cheap checks BEFORE calling the prover. Build `pks_per_message` (N atts in body order + proposer last, canonical order §2.x) and `messages` (att-data-root,slot then block-root,block.slot). **Use the attestation `pubkey_cache` for the N attestation components, but resolve the proposer (last) component's PROPOSAL pubkey OUTSIDE that cache (codex P1) — the cache is keyed by validator index and holds attestation keys; a proposer who also attested would otherwise verify with the wrong key and the valid block would be rejected.** Call `xmss.verifyType2(container.proof, pks_per_message, messages)`. Delete the per-attestation loop and the participant cross-check. Delete `verifySignaturesParallel`, `AggregatedPayloadVerifyBatch` task prep. Rename metrics to `lean_pq_sig_block_proof_*`.

- [ ] **Step 4: Add the order + cap + bitlist tests**

```zig
test "verifySignatures rejects > MAX_ATTESTATIONS_DATA distinct entries" { ... }
test "verifySignatures rejects swapped proposer/attestation order" {
    // build Type-2 with proposer NOT last; EXPECT verify failure
}
test "verifySignatures rejects empty aggregation_bits" { ... }
test "verifySignatures rejects out-of-range validator bit" { ... }
test "verifySignatures happy path verifies a well-formed block" { ... }
```

- [ ] **Step 5: Run tests, expect pass. Commit.**

```bash
git add pkgs/state-transition/src/transition.zig
git commit -m "feat(stf): single Type-2 verify_signatures with structural checks"
```

### Task 8: Block production — produceBlock + validator_client signing

**Files:**
- Modify: `pkgs/node/src/chain.zig` (`ProducedBlock`, `produceBlock`, new `resolveSigningPubkeys`, `mergeBlockProof`)
- Modify: `pkgs/node/src/forkchoice.zig` (`getProposalAttestations` return field rename)
- Modify: `pkgs/node/src/validator_client.zig` (`_sign_block` equivalent)
- Modify: `pkgs/key-manager/src/lib.zig` (none — `signBlockRoot` returns `SIGBYTES`; lift at callsite)
- Test: `pkgs/node/src/chain.zig` in-file

- [ ] **Step 1: Failing test — produced block verifies under verifySignatures**

```zig
test "validator_client produced block carries a verifiable Type-2 proof" {
    // produce a block with >=1 attestation, sign it, then run
    // stf.verifySignatures on it against the pre-state. EXPECT success.
}
```

- [ ] **Step 2: Run, expect failure** (ProducedBlock still has attestation_signatures; SignedBlock built with `.signature`).

- [ ] **Step 3: Change ProducedBlock + produceBlock**

`ProducedBlock { block, blockRoot, attestation_type1s: std.ArrayList(TypeOneMultiSignature) }`. Rename `getProposalAttestations` result field to `attestation_type1s` (forkchoice.zig:1330,3637 and the `.signatures` reads at 1269/2070/2201 — read those first, they may be unrelated SignaturesMap uses; only the block-production result rename applies). Update `produceBlock`'s body (chain.zig:2516-2560) to carry the renamed list, no proposer/merge here.

- [ ] **Step 4: Add `resolveSigningPubkeys` + `mergeBlockProof` to chain**

`resolveSigningPubkeys(block, attestation_type1s, proposer_index) ![]OwnedPubkeyBytes` — takes the produced BLOCK / participant layout (codex P2 round 3 — a root/state lookup gives validators but NOT the body's `aggregation_bits`/participants/order, so the resolver can't know which keys to copy from the root alone). Takes `states_lock.shared`, COPIES OUT only the needed small set (proposer PROPOSAL pubkey + each attestation component's participant ATTESTATION pubkeys, canonical Type-2 order §2.x), RELEASES the lock, returns owned bytes. Do NOT copy all validator keys; do NOT return a live `*BeamState` borrow held across the merge — mirror `produceBlock`'s `cloneAndRelease` snapshot-then-release (chain.zig:2468-2486). Holding `states_lock` across the prover would stall block import on `states_lock.exclusive` (the #863 stall). `mergeBlockProof(parts, pks_per_part) ![]u8` — dispatches `xmss.mergeType1ToType2` on the chain worker (mirror `submitGossipAttestation` dispatch), lock-free, returns the RAW type2 wire (lz4+postcard, no SSZ framing). Read the chain-worker dispatch pattern first.

- [ ] **Step 5: Rewrite validator_client block path** per design §4.2

Replace the `SignedBlock{ .signature = ... }` literal (validator_client.zig:151-157) with: lift `signBlockRoot` bytes via `xmss.Signature.fromBytes`; build proposer singleton Type-1 (`participants` = only proposer index); get owned pubkey bytes via `chain.resolveSigningPubkeys(produced_block.block, produced_block.attestation_type1s, slot_proposer_id)`; build `pks_per_part` (`buildPubkeysPerPart`, canonical order §2.x — attestations in body order, proposer LAST); `raw = chain.mergeBlockProof([*attestation_type1s, proposer_type1], pks_per_part)`; **wrap the raw wire in the SSZ container (codex P1 §2.y): `SignedBlock.proof = ssz_encode(TypeTwoMultiSignature{proof: ByteList512KiB(raw)})` — do NOT store `raw` directly, leanSpec's wire format is the SSZ-framed container.** `SignedBlock{ .block, .proof }`. Proposer entry LAST.

- [ ] **Step 6: Run test, expect pass. Commit.**

```bash
git add pkgs/node/src/chain.zig pkgs/node/src/forkchoice.zig pkgs/node/src/validator_client.zig
git commit -m "feat(node): produce blocks with merged Type-2 proof"
```

### Task 9: chain.onBlock — keep eager tracker weight, drop the proof-write loop

**CORRECTED after codex review.** zeam fork-choice weight comes from `AttestationTracker`
(`self.attestations`), fed by `onAttestationUnlocked(att, is_from_block=true)` — NOT from the
payload maps. So block votes get weight EAGERLY at import (unchanged from devnet4). There is no
deferral and no empty-key stamping. The only thing that changes here: the old
`storeAggregatedPayload(is_from_block=true)` loop (which consumed per-attestation proofs that no
longer exist on the block) is removed; proof recovery moves to deconstruction (Task 12).

**Files:**
- Modify: `pkgs/node/src/chain.zig` (onBlock; verify call site 3273-3277; the post-STF attestation loop ~3450-3470)
- Modify: `pkgs/node/src/forkchoice.zig` (delete the `is_from_block=true` branch of `storeAggregatedPayload`; KEEP `onAttestationUnlocked`)
- Test: `pkgs/node/src/chain.zig` in-file

- [ ] **Step 1: Failing test — block votes get tracker weight at import**

```zig
test "onBlock applies block-attestation weight to the tracker at import" {
    // import a block with body attestations whose votes were NOT seen via gossip;
    // assert the participating validators' AttestationTracker.latestKnown is updated
    // immediately (head weight reflects the block votes without waiting for a tick).
}
```

- [ ] **Step 2: Run, expect failure** (block built with `.signature`; old proof loop present).

- [ ] **Step 3: Collapse the verify call site**

chain.zig:3273-3277 → `try stf.verifySignatures(self.allocator, pre_snapshot, &signedBlock, &self.public_key_cache);`. Remove the `if (self.thread_pool)` parallel branch for verify only.

- [ ] **Step 4: Keep the eager tracker update; remove only the proof-write loop**

Read chain.zig:3440-3475 first. The per-validator `forkChoice.onAttestation(att_for_validator, is_from_block=true)` calls (subsystem A — fork-choice weight) STAY exactly as they are; they use the trusted `aggregation_bits`, need no proof. KEEP the existing log-and-continue on `InvalidAttestation`/unknown-head there (documented exception — an unknown head during sync is not a malformed block; see design §5 hard-error policy). REMOVE only the `storeAggregatedPayload(..., is_from_block=true)` calls (subsystem B — they required per-attestation proofs that no longer exist). Do NOT add empty-key stamping. Delete the `is_from_block=true` branch in `forkchoice.zig:storeAggregatedPayload`. Update the `chain.zig:3337` `proof_data` comment to `proof`. **Ordering note (codex P1, two rounds):** Task 12 inserts the fallible `deconstructCompute` call BEFORE `forkChoice.onBlock` (the protoarray insert at :3362), and `deconstructCommit` after the tracker loop — so a deconstruction hard-reject leaves protoarray AND tracker untouched. Leave the tracker loop where it is for now; Task 12 places compute ahead of `forkChoice.onBlock` and commit after.

- [ ] **Step 5: Run test, expect pass. Commit.**

```bash
git add pkgs/node/src/chain.zig pkgs/node/src/forkchoice.zig
git commit -m "node, forkchoice: keep eager block-vote tracker weight; drop per-attestation proof writes"
```

---

## Phase 4 — Deconstruction

### Task 10: `deconstruct.zig` skeleton + no-op cases

**Files:**
- Create: `pkgs/node/src/deconstruct.zig`
- Modify: `pkgs/node/src/lib.zig` (export)
- Test: in `deconstruct.zig`

- [ ] **Step 1: Failing tests for the trivial cases**

```zig
test "deconstruct: empty body returns empty result" { ... }
test "deconstruct: all attestations already covered locally → empty result, no writes" { ... }
test "deconstruct: target.slot <= justified.slot → skipped" { ... }
```

- [ ] **Step 2: Run, expect failure** (module/function undefined).

- [ ] **Step 3: Implement `StagedDeconstruct` + `deconstructCompute` skeleton**

Per §6 (compute/commit split — codex P1). `deconstructCompute(allocator, fork_choice, signed_block, parent_state) !StagedDeconstruct`. Implement: empty-body short-circuit; **SSZ-decode `signed_block.proof` → `TypeTwoMultiSignature` container, use `container.proof` (raw wire) for splits (§2.y)**; build `pks_per_message`; snapshot + index local partials by `hash_tree_root(AttestationData)` under `signatures_mutex` (release before any prover call); per-attestation skip checks (`target.slot <= justified.slot`, `block_participants ⊆ local_union`). Leave the split+merge as the next task (return empty staged for now so the no-op tests pass). Also stub `deconstructCommit(fork_choice, staged) StagedAggregates` returning empty.

- [ ] **Step 4: Run trivial tests, expect pass. Commit.**

```bash
git add pkgs/node/src/deconstruct.zig pkgs/node/src/lib.zig
git commit -m "feat(node): deconstruct module skeleton + skip-path tests"
```

### Task 11: deconstruction split + merge + store mutation

**Files:**
- Modify: `pkgs/node/src/deconstruct.zig`
- Test: in `deconstruct.zig`

- [ ] **Step 1: Failing tests for the active paths**

```zig
test "deconstruct: unseen attestation → split, write as-is, emit aggregate" { ... }
test "deconstruct: locally-seen subset → split + merge with partial → combined replaces partial" { ... }
test "deconstruct: partial overlap local {A} + block {A,B} → no double-count" { ... }
test "deconstruct: overlapping local partials {C,D}+{D,E} + block {A,B} → greedy union, D once" { ... }
test "deconstruct: mixed golden — covered + unseen + below-justified in one block" { ... }
```

- [ ] **Step 2: Run, expect failure.**

- [ ] **Step 3: Implement the COMPUTE active path** per §6.3 (no pool mutation)

In `deconstructCompute`: `splitType2ByMessage(container.proof, ...)` (resolve proposer-component pubkey OUTSIDE the attestation cache per codex P1; the split layout includes the proposer entry) → restore participants from att bits → **select local partials greedily against an ACCUMULATED union (codex P2 rounds 3+4 — a validator must not appear in two children of one `aggregateType1` call; "disjoint from the block component" is insufficient because two local partials can overlap each other, e.g. block `{A,B}` + local `{C,D}` + `{D,E}` → D twice). Use the spec's `select_greedily` pattern: `covered = block_participants`; for each partial, select only if it adds validators ∉ covered, then `covered |= partial.validators`.** → if any selected: `aggregateType1(component + selected)` else use component as-is → STAGE `(combined, superseded-partials, data)` into `StagedDeconstruct`. NO pool write here. Prover calls run lock-free (snapshot taken in Task 10, released before these calls).

- [ ] **Step 4: Implement INFALLIBLE COMMIT** per §6 (compute/commit split — codex P1; infallible commit — codex P2 round 4; CORRECTED lock — codex P2)

`deconstructCommit(fork_choice, staged) StagedAggregates` — **must NOT fail** (it runs after the fork-choice mutations; a failure here would report a failed import after protoarray/tracker were already changed). Re-acquire `forkChoice.signatures_mutex` (payload-map lock, NOT the main `forkChoice.mutex`). `SyncMutex` is exclusive-only. Mutate `latest_new_aggregated_payloads`: insert combined under the block's `data` key via `sszClone` (idempotent), and remove superseded partials best-effort (a rotation may have already moved them to `latest_known` — leave those; the greedy set-cover at build/aggregation time dedups the harmless redundancy). NO `error.RaceDuringDeconstruct`, NO retry — the race is benign (combined ⊇ partials). Build the `SignedAggregatedAttestation` list to return. Never hold the main `mutex` across prover calls (those happened in compute). Add `lean_block_deconstruct_seconds` / `lean_block_deconstruct_recovered_bytes` metrics.

- [ ] **Step 5: Add error-path tests**

```zig
test "deconstructCompute: missing parent state → error.MissingParentState" { ... }
test "deconstructCompute: malformed Type-2 → error.Type2DecodeFailed" { ... }
test "deconstructCommit: rotation moved a partial to known between compute and commit → still commits combined, no error" { ... }
```

- [ ] **Step 6: Run all deconstruct tests, expect pass. Commit.**

```bash
git add pkgs/node/src/deconstruct.zig
git commit -m "feat(node): deconstruct split+merge+store mutation with race handling"
```

### Task 12: Wire compute→fc→commit into onBlock + thread aggregates to BeamNode

**Files:**
- Modify: `pkgs/node/src/chain.zig` (onBlock: COMPUTE before `forkChoice.onBlock`; COMMIT after the tracker loop)
- Modify: `pkgs/node/src/node.zig` (the block-import caller that owns the `BeamNode` pointer — publish recovered aggregates there)
- Test: `pkgs/node/src/chain.zig` in-file

- [ ] **Step 1: Failing test — deconstruction recovers proofs into latest_new (not weight)**

```zig
test "onBlock deconstruction recovers Type-1 proofs into latest_new_aggregated_payloads" {
    // import a block carrying an attestation whose proof was NOT seen via gossip;
    // assert latest_new_aggregated_payloads now holds a recovered Type-1 for that
    // AttestationData. (Fork-choice weight is already covered by Task 9's tracker
    // test — this test is about PROOF availability for block building, not weight.)
}
test "onBlock rejects the whole block when deconstruction fails, tracker untouched" {
    // force a deconstruction hard error (e.g. missing parent state); assert onBlock
    // returns an error AND the AttestationTracker was NOT mutated with this block's votes.
}
```

- [ ] **Step 2: Run, expect failure.**

- [ ] **Step 3: Wire COMPUTE→fc→COMMIT order + publish path (codex P1/P2)**

Read chain.zig:3361-3493 first (the `fcprocessing` block — note `forkChoice.onBlock` protoarray insert is at :3362, BEFORE the tracker loop at :3466). Wire in this exact order:
1. After `apply_transition`: `staged = deconstructCompute(...)` (obtain `parent_state` via `statesGet(block.parent_root)`). This is the fallible/hard-reject step — it runs BEFORE `forkChoice.onBlock` so a failure rejects the block with protoarray AND tracker untouched (codex P1, two rounds). No fallback — propagate the error (whole-block reject, design §5).
2. `forkChoice.onBlock(...)` (protoarray insert) → the per-validator `onAttestationUnlocked(is_from_block=true)` tracker loop (Task 9).
3. After those succeed: `aggregates = deconstructCommit(forkChoice, staged)` — **infallible** pool write (codex P2 round 4): idempotent insert + best-effort remove, no error/retry, because it runs after fork-choice was already mutated. A benign rotation race just means "remove superseded" is a partial no-op.

Publishing (codex P2): `BeamChain` has NO `node` field, so do NOT call `self.node.publishProducedAggregations(...)` inside `chain.onBlock`. Have `onBlock` surface the committed aggregates to its caller (return / out-param), and publish from the `node.zig` block-import path that holds the `BeamNode` pointer (mirror how `submitAggregateOnInterval` hands a `BeamNode*` to the aggregate worker). Publish only when `is_aggregator_enabled`. Read the existing aggregate-publish wiring first.

- [ ] **Step 4: Run test, expect pass. Commit.**

```bash
git add pkgs/node/src/chain.zig pkgs/node/src/node.zig
git commit -m "node: deconstruct before tracker update; publish recovered aggregates via BeamNode"
```

---

## Phase 5 — Spectest, hive driver, serialization, test fixtures

### Task 13: Spectest runners + leanSpec submodule bump

**Files:**
- Modify: `.gitmodules` / submodule pointer `leanSpec`
- Modify: `pkgs/spectest/src/runner/verify_signatures_runner.zig`
- Modify: `pkgs/spectest/src/runner/ssz_runner.zig`
- Modify: `pkgs/spectest/src/runner/fork_choice_runner.zig`
- Modify: `pkgs/spectest/src/runner/networking_codec_runner.zig`

- [ ] **Step 1: Bump leanSpec submodule to the devnet5 fixture commit**

```bash
cd leanSpec && git fetch origin && git checkout <devnet5-fixture-commit> && cd ..
```
(Use PR #717 head `1db9e4d0` or the merged devnet5 commit/tag.)

- [ ] **Step 2: Rewrite verify_signatures_runner** per §7.2

Parse `signedBlock.proof` → `ByteList512KiB`; build `pks_per_message` + `messages` (mirror Task 7); call `xmss.verifyType2`; pass/fail == fixture expectation. Delete `parseAggregatedSignatureProof`, attestation-signature + proposer-signature parsing. If Task 0 = (B1/B2), dispatch test-scheme via `leanEnv` and drop the `:134` skip; if (A-fallback), keep the skip.

- [ ] **Step 3: Update ssz_runner + fork_choice_runner + networking_codec_runner** per §7.3/7.4/7.6

Add `TypeTwoMultiSignature` SSZ case; update `SignedBlock` shape + 512 KiB cap; shared block parser → new envelope; container-binding swaps.

- [ ] **Step 4: Regenerate + run spectest**

Run: `ASDF_ZIG_VERSION=0.16.0 zig build spectest 2>&1 | tail -40`
Expected: devnet5 verify_signatures / ssz / fork_choice / networking_codec fixtures pass (test-scheme aggregation fixtures pass if B-path, else skipped).

- [ ] **Step 5: Commit**

```bash
git add .gitmodules leanSpec pkgs/spectest/src/runner/
git commit -m "feat(spectest): devnet5 fixtures + Type-2 runners"
```

### Task 14: Hive test driver

**Files:**
- Modify: `pkgs/cli/src/test_driver.zig`

- [ ] **Step 1: Update verify_signatures/run endpoint** per §7.5

Parse `signedBlock.proof` → Type-2 verify (mirror Task 7). Delete proposer/attestation-signature parsing (test_driver.zig:1160-1254).

- [ ] **Step 2: Update aggregated-attestation gossip parsing**

`proof` field rename (`proof_data` → `proof`); `AggregatedSignatureProof.init` → `TypeOneMultiSignature.init` (681, 843); dual-key lookups → `&.{ "proof" }`.

- [ ] **Step 3: Build CLI**

Run: `ASDF_ZIG_VERSION=0.16.0 zig build 2>&1 | tail -20`
Expected: test_driver compiles.

- [ ] **Step 4: Commit**

```bash
git add pkgs/cli/src/test_driver.zig
git commit -m "feat(test-driver): Type-2 verify_signatures + Type-1 gossip parsing"
```

### Task 15: Network serialization + test helpers + deletion sweep

**Files:**
- Modify: `pkgs/network/src/ethlibp2p.zig`, `pkgs/node/src/network.zig`
- Modify: `pkgs/node/src/testing.zig`, `pkgs/database/src/test_helpers.zig`

- [ ] **Step 1: Swap type bindings**

`AggregatedSignatureProof` → `TypeOneMultiSignature` at all binding sites. `testing.zig:246` `aggregateSignatures` → `aggregateType1` with `proof` out-param. Add shared `buildSignedBlockProof(...)` test helper for the Type-2 envelope; use it where tests construct `SignedBlock`.

- [ ] **Step 2: Deletion sweep — grep must reach zero**

Run each; expected: no matches (except comments/docs):
```bash
grep -rn "AggregatedSignatureProof\|proof_data\|ByteListMiB\|BlockSignatures\|AttestationSignatures\|signed_block\.signature\|verifySignaturesParallel\|verifyAggregatedPayload\|aggregateSignatures\b" pkgs/ rust/
grep -rn "xmss_aggregate\b\|xmss_verify_aggregated\|AggregatedXMSS\|INV_PROOF_SIZE" pkgs/ rust/
```

- [ ] **Step 3: Full build + full test**

Run: `ASDF_ZIG_VERSION=0.16.0 zig build && ASDF_ZIG_VERSION=0.16.0 zig build test 2>&1 | tail -40`
Expected: clean build, all unit tests pass.

- [ ] **Step 4: Commit**

```bash
git add pkgs/network/src/ethlibp2p.zig pkgs/node/src/network.zig pkgs/node/src/testing.zig pkgs/database/src/test_helpers.zig
git commit -m "refactor: complete devnet5 type migration; remove devnet4 aggregation surface"
```

---

## Phase 6 — Validation

### Task 16: Type-2 size budget smoke test

**Files:**
- Test: `pkgs/node/src/chain.zig` or `pkgs/types/src/block.zig` in-file

- [ ] **Step 1: Write the test**

```zig
test "MAX_ATTESTATIONS_DATA-full block Type-2 fits in 512 KiB" {
    // build a block with MAX_ATTESTATIONS_DATA distinct AttestationData,
    // each with a realistic participant count; merge to Type-2; assert
    // encoded length <= MAX_AGGREGATE_PROOF_SIZE.
}
```

- [ ] **Step 2: Run, expect pass** (or FAIL → wire cap wrong → escalate per risk #1 before merging).

- [ ] **Step 3: Commit**

```bash
git add <test file>
git commit -m "test: Type-2 proof fits in 512 KiB at MAX_ATTESTATIONS_DATA"
```

### Task 17: Full suite + spectest + shadow-test note

- [ ] **Step 1: Run everything**

Run: `ASDF_ZIG_VERSION=0.16.0 zig build test && ASDF_ZIG_VERSION=0.16.0 zig build spectest 2>&1 | tail -40`
Expected: all green.

- [ ] **Step 2: Update RELEASE.md** — fresh-datadir requirement for devnet5 (no migration).

- [ ] **Step 3: Note shadow-testing** — before declaring done, run the shadow network (see memory `shadow-testing.md`) to validate prover throughput (production merge + deconstruction split) under load. Watch `lean_block_deconstruct_seconds`.

- [ ] **Step 4: Commit**

```bash
git add RELEASE.md
git commit -m "docs: devnet5 release notes (fresh datadir required)"
```

---

## Self-review notes

- **Spec coverage:** every design §1-8 maps to a task (FFI→T1-3, types→T4-6, verify/import→T7-9, deconstruct→T10-12, spectest/hive/serial→T13-15, validation→T16-17, test-config gate→T0).
- **Type consistency:** `TypeOneMultiSignature`/`TypeTwoMultiSignature`/`ByteList512KiB`/`MessageBinding`/`attestation_type1s`/`resolveSigningPubkeys(block,…)`/`mergeBlockProof`/`deconstructCompute`/`deconstructCommit`/`StagedDeconstruct`/`StagedAggregates` used consistently across tasks. (Corrected after 3 codex rounds: removed `stampKnownAttestationDataKey` — no empty-key stamping; `borrowStateForSigning` → `resolveSigningPubkeys(block,attestation_type1s,proposer_index)` — copy-out-and-release, takes the block layout; split single `deconstructBlockIntoStore` → `deconstructCompute` (fallible, before fork-choice mutation) + `deconstructCommit` (infallible, after); SignedBlock.proof = SSZ(TypeTwoMultiSignature) wire layer.)
- **Known soft spots (flagged inline, not placeholders):** exact `rec_aggregation` Rust signatures (arg order, Result vs panic, message-binding shape) must be confirmed against rev `f33a0775` during Task 2 — the leanMultisig-py v0.0.5 wrapper is the reference. These are real "confirm against upstream" actions, not vague TODOs.
