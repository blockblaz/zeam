# Plan: Pre-generated Validator Keys for CI

## Problem

XMSS key generation via `hashsig_keypair_generate` (Rust FFI) is extremely slow. Every CI run and every `getTestKeyManager` call generates keys from scratch. For 3 validators with 1000 active epochs, this adds significant time to:

1. **Unit tests** — any test touching key-manager or state-transition with signatures
2. **Simtests** — the `beam` CLI command generates 3 validators inline via `getTestKeyManager`
3. **Spec tests** — fixture runners that need signed blocks

## Current Flow

```
CLI main.zig (beam command)
  → getTestKeyManager(allocator, 3, 1000)
    → for each validator:
      → getOrCreateCachedKeyPair(i, 1000)
        → KeyPair.generate(seed="test_validator_{i}", activation=0, epochs=1000)
          → hashsig_keypair_generate() [Rust FFI — SLOW]
```

There IS an in-memory cache (`global_test_key_pair_cache`) but it only survives within a single process — doesn't help across test runs or CI.

## Proposed Solution

Pre-generate 32 validator key pairs as SSZ files, commit them to the repo, and load them instead of generating at runtime.

### Key Format (matching leanSpec/ream structure)

```
resources/test-keys/
├── validator-keys-manifest.yaml
└── hash-sig-keys/
    ├── validator_0_sk.ssz    # Private key (SSZ-encoded)
    ├── validator_0_pk.ssz    # Public key (SSZ-encoded)
    ├── validator_1_sk.ssz
    ├── validator_1_pk.ssz
    ├── ...
    ├── validator_31_sk.ssz
    └── validator_31_pk.ssz
```

### Manifest Format (compatible with leanSpec)

```yaml
key_scheme: SIGTopLevelTargetSumLifetime32Dim64Base8
hash_function: Poseidon2
encoding: TargetSum
lifetime: 1000
log_num_active_epochs: 10
num_active_epochs: 1000
num_validators: 32
validators:
  - index: 0
    pubkey_hex: "0x..."
    privkey_file: validator_0_sk.ssz
  - index: 1
    pubkey_hex: "0x..."
    privkey_file: validator_1_sk.ssz
  # ... up to 31
```

## Implementation Steps

### Step 1: Add `keygen` command to zeam-tools

Add a `keygen` subcommand to `pkgs/tools/src/main.zig` that:

1. Takes `--num-validators N`, `--num-active-epochs E`, `--output-dir DIR`
2. Generates N keypairs using deterministic seeds (`test_validator_{i}`)
3. Serializes each keypair to `{dir}/hash-sig-keys/validator_{i}_sk.ssz` and `_pk.ssz`
4. Writes `{dir}/validator-keys-manifest.yaml` with pubkey hex and metadata

### Step 2: Generate and commit 32 keys

```bash
zig build tools
./zig-out/bin/zeam-tools keygen --num-validators 32 --num-active-epochs 1000 --output-dir resources/test-keys
```

Commit `resources/test-keys/` to the repo. These are test keys with known seeds — no security concern.

### Step 3: Update `getTestKeyManager` to load pre-generated keys

Modify `pkgs/key-manager/src/lib.zig`:

```zig
pub fn getTestKeyManager(
    allocator: Allocator,
    num_validators: usize,
    max_slot: usize,
) !KeyManager {
    // Try loading pre-generated keys first
    if (num_validators <= 32) {
        if (loadPreGeneratedKeys(allocator, num_validators)) |km| {
            return km;
        } else |_| {
            // Fall through to runtime generation
        }
    }
    // ... existing runtime generation as fallback
}

fn loadPreGeneratedKeys(allocator: Allocator, num_validators: usize) !KeyManager {
    var km = KeyManager.init(allocator);
    errdefer km.deinit();

    for (0..num_validators) |i| {
        const sk_path = std.fmt.comptimePrint(
            "resources/test-keys/hash-sig-keys/validator_{d}_sk.ssz", .{i}
        );
        // ... read SSZ files and call KeyPair.fromSsz()
    }
    return km;
}
```

**Note**: Need to handle path resolution — keys are relative to repo root. Could use `@embedFile` to compile them in, or resolve at runtime relative to the executable.

### Step 4: Option A — `@embedFile` (preferred for tests)

Embed the SSZ key data at compile time so tests don't need to find files at runtime:

```zig
const embedded_keys = struct {
    const sk_0 = @embedFile("resources/test-keys/hash-sig-keys/validator_0_sk.ssz");
    const pk_0 = @embedFile("resources/test-keys/hash-sig-keys/validator_0_pk.ssz");
    // ... generate these with comptime
};
```

But 32 keys × ~10MB per private key = ~320MB embedded — too large.

### Step 4: Option B — Runtime file loading (preferred)

Load from disk relative to a known path. The build system can pass the resource path as a build option:

```zig
// In build.zig
const test_keys_path = b.option([]const u8, "test-keys-path", "Path to pre-generated test keys") 
    orelse "resources/test-keys";
```

### Step 5: Update CI workflow

No changes needed if keys are committed to the repo and `getTestKeyManager` loads them automatically. The existing CI steps will just be faster.

### Step 6: Update `beam` CLI command

The `beam` command in `main.zig` currently calls `getTestKeyManager(allocator, 3, 1000)`. After this change, it will automatically use pre-generated keys when available — no CLI changes needed.

## Key Storage: Separate Repo

Keys will be stored in a separate repo (like leanSpec's approach with `leanEthereum/leansig-test-keys`):

- **Repo**: `blockblaz/zeam-test-keys` (or under leanEthereum org if shared across clients)
- **Added to zeam as a git submodule** at `test-keys/`
- **CI caches** the submodule to avoid cloning every time

### Submodule Integration
```bash
git submodule add https://github.com/blockblaz/zeam-test-keys.git test-keys
```

CI workflow update:
```yaml
- uses: actions/checkout@v4
  with:
    submodules: recursive  # Already done for leanSpec
```

### `getTestKeyManager` loads from submodule:
```zig
fn loadPreGeneratedKeys(allocator: Allocator, num_validators: usize) !KeyManager {
    var km = KeyManager.init(allocator);
    for (0..num_validators) |i| {
        // Path relative to repo root (zig build runs from there)
        const sk = try loadFile(allocator, "test-keys/hash-sig-keys/validator_{d}_sk.ssz", i);
        const pk = try loadFile(allocator, "test-keys/hash-sig-keys/validator_{d}_pk.ssz", i);
        var keypair = try xmss.KeyPair.fromSsz(allocator, sk, pk);
        try km.addKeypair(i, keypair);
    }
    return km;
}
```

## Callers of getTestKeyManager (all benefit)

| Location | Validators | max_slot |
|----------|-----------|----------|
| `cli/src/main.zig` (beam cmd) | 3 | 1000 |
| `node/src/chain.zig` (test) | 4 | 3 |
| `node/src/node.zig` (test) | num_validators | 10 |
| `node/src/testing.zig` | configurable | configurable |
| `state-transition/src/mock.zig` | num_validators | numBlocks |
| `types/src/block_signatures_testing.zig` | num_validators | 10 |

## Questions for Anshal

1. **Repo org**: `blockblaz/zeam-test-keys` or `leanEthereum/zeam-test-keys`? Or reuse the existing `leanEthereum/leansig-test-keys`?

2. **Seed determinism**: Currently using `"test_validator_{i}"` as seed. Keep this for reproducibility?

3. **num_active_epochs**: 1000 matches the CLI default. Enough?

4. **Manifest format**: Match leanSpec's `validator-keys-manifest.yaml` exactly for cross-client compatibility?

## Impact

- **CI speedup**: Key loading from SSZ is near-instant vs minutes for generation
- **Test reliability**: No more flaky timing issues from key generation
- **Compatibility**: Same key format as leanSpec/ream — keys can be shared across implementations
- **Repo size**: Zero impact on zeam repo (keys in separate repo as submodule)
