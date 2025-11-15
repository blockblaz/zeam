# Zeam Integration Tests

This directory contains integration tests for the Zeam lean consensus client.

## Tests

### 1. `beam_integration_test.zig`
Tests the beam command with mock network and SSE event streaming.

### 2. `genesis_to_finalization_test.zig`
Two-node test that spawns zeam nodes directly and monitors them to finalization.

### 3. `lean_quickstart_integration_test.zig`
**Full lean-quickstart integration test (Option B)**. Uses the lean-quickstart scripts for genesis generation and node spawning.

---

## lean-quickstart Integration Test

### Overview

The `lean_quickstart_integration_test.zig` implements a full end-to-end test using the [lean-quickstart](https://github.com/blockblaz/lean-quickstart) tooling. This test:

1. Uses lean-quickstart's `generate-genesis.sh` (PK's eth-beacon-genesis Docker tool)
2. Uses lean-quickstart's `spin-node.sh` to spawn zeam nodes
3. Monitors nodes for finalization via SSE events
4. Cleans up using SIGTERM signals (mimics Ctrl+C)

### Required Changes to lean-quickstart

For the test to work properly, the following changes are needed in the `lean-quickstart` submodule:

#### **File: `client-cmds/zeam-cmd.sh`**

The zeam command needs these additions:

```bash
# Extract genesis time from config.yaml to ensure both nodes use same genesis time
genesisTime=$(yq eval '.GENESIS_TIME' "$configDir/config.yaml")

node_binary="$scriptDir/../zig-out/bin/zeam node \
      --custom_genesis $configDir \
      --validator_config $validatorConfig \
      --override_genesis_time $genesisTime \     # ← ADD THIS
      --network-dir $dataDir/$item/network \      # ← ADD THIS
      --data-dir $dataDir/$item \
      --node-id $item \
      --node-key $configDir/$item.key \
      --metrics_enable \                          # ← ADD THIS
      --metrics_port $metricsPort"                # ← FIX: Use underscore not hyphen
```

**Required changes:**
1. **Add `--override_genesis_time`**: Extract from config.yaml and pass to zeam
2. **Add `--network-dir`**: Each node needs isolated network directory
3. **Add `--metrics_enable`**: Required flag to enable metrics endpoint
4. **Fix `--metrics_port`**: Must use underscore `_` not hyphen `-`

#### **File: `client-cmds/zeam-cmd.sh` - Set Binary Mode**

```bash
# Use binary mode by default since lean-quickstart is a submodule in zeam repo
node_setup="binary"  # ← Change from "docker" to "binary"
```

#### **File: `spin-node.sh` - Optional Improvements**

These are optional but recommended:

1. **Make sudo optional** (line 102-110):
```bash
# Only use sudo if explicitly requested
if [ -n "$useSudo" ]; then
    cmd="sudo rm -rf $itemDataDir/*"
else
    cmd="rm -rf $itemDataDir/*"
fi
```

2. **Use $scriptDir for relative paths** (line 113, 120):
```bash
source "$scriptDir/parse-vc.sh"            # ← Add $scriptDir/
sourceCmd="source $scriptDir/client-cmds/$client-cmd.sh"  # ← Add $scriptDir/
```

### Requirements

1. **Docker**: For PK's `eth-beacon-genesis` tool (genesis generation)
2. **yq**: YAML processor for parsing configuration
3. **zeam binary**: Must be built (`zig build`) before running test
   - Binary should be at `zig-out/bin/zeam`
4. **bash**: The lean-quickstart scripts use bash

### Platform Compatibility

#### **Linux (GitPod, CI)**
✅ **Fully working** - All tests pass including finalization

#### **macOS**
⚠️ **Partial support** - Tests run but validator activation issue:
- Genesis generation: ✅ Works
- Node spawning: ✅ Works
- Node connectivity: ✅ Works
- Validator activation: ❌ **Only validator 0 activates, validator 1 doesn't**
- Finalization: ❌ Fails (due to only 50% stake active)

**macOS Issue:**
This appears to be a platform-specific bug in zeam's validator initialization or libp2p networking layer. Both `genesis_to_finalization_test.zig` and `lean_quickstart_integration_test.zig` exhibit the same behavior on macOS.

**Known symptoms on macOS:**
- Only validator index 0 produces blocks and votes
- Validator index 1 never appears in logs
- No justification beyond genesis
- No finalization occurs
- "Address already in use" panics may occur

**Workaround:** Run tests on Linux for full functionality.

### Running the Test

```bash
# Build zeam first
zig build

# Run all integration tests
zig build simtest

# On Linux, expect: All tests pass including finalization
# On macOS, expect: Tests run but timeout (validator issue)
```

### Test Configuration

The test creates a network with:
- 2 validators (1 per node)
- Metrics ports: 9669 (zeam_0), 9670 (zeam_1)
- QUIC ports: 9100 (zeam_0), 9101 (zeam_1)
- 600 second timeout for finalization
- Test directory: `test_lean_quickstart_network/`

### Architecture

```
Test Process
  ├─ Generate genesis via generate-genesis.sh (Docker)
  ├─ Spawn zeam_0 via spin-node.sh
  │    └─ spin-node.sh spawns zeam binary in background
  │         └─ zeam node runs with validator 0
  ├─ Spawn zeam_1 via spin-node.sh
  │    └─ spin-node.sh spawns zeam binary in background
  │         └─ zeam node runs with validator 1
  ├─ Monitor finalization via SSE events
  └─ Cleanup via SIGTERM (triggers script trap)
```

### Key Implementation Details

1. **Working Directory**: Process.Child.cwd set to `lean-quickstart/` so relative paths work
2. **Environment**: `NETWORK_DIR` passed as relative path (`../test_network`)
3. **Signal Handling**: Uses SIGTERM (not SIGKILL) to trigger lean-quickstart's cleanup trap
4. **Process Management**: Custom `NodeProcess` struct manages child process lifecycle

### Known Issues

1. **macOS validator activation**: Only validator 0 active (platform-specific zeam bug)
2. **bash compatibility**: `wait -n` on line 173 of spin-node.sh fails on macOS bash 3.2 (but non-fatal)
3. **SSE connection crashes**: Race condition in api_server.zig when connection closes

### Future Work

- [ ] Debug macOS validator activation issue
- [ ] Fix SSE connection close race condition  
- [ ] Consider adding conditional test execution based on platform
- [ ] Add metrics to track validator participation percentage

