# Zeam Test Fixtures

This guide shows how to set up and run two zeam nodes locally that can communicate and achieve finalization. You'll create your own genesis configuration with two zeam nodes (zeam_0 and zeam_1) that can achieve finalization with 3 validators total.

## Directory Structure

After following the setup steps, you'll have:

```
genesis/
├── config.yaml            # Genesis and validator settings
├── nodes.yaml             # Node ENRs for network discovery
├── validators.yaml        # Validator assignment (zeam_0, zeam_1)
├── validator-config.yaml  # Node configurations with private keys
├── node0/
│   └── key               # Private key for zeam_0
└── node1/
    └── key               # Private key for zeam_1
```

## Quick Start: Running Two Nodes

Follow these steps to run two zeam nodes from the repository root:

### Step 0: Generate Genesis Timestamp

```bash
GENESIS_TIME=$(date +%s)
echo "Genesis time: $GENESIS_TIME"
```

**Important:** Save this timestamp! You'll need to use the SAME value in both terminals.

### Step 1: Build the Project

```bash
# Build the main project
zig build -Doptimize=ReleaseFast

# Build the tools for ENR generation
zig build tools -Doptimize=ReleaseFast
```

### Step 2: Create Genesis Directory Structure

```bash
# Create the genesis directory structure
mkdir -p genesis/node0 genesis/node1

# Create data directories for the nodes
mkdir -p data/test_node0 data/test_node1
```

### Step 3: Generate Private Keys

```bash
# Node 0 private key (64 hex chars, no newline)
printf "$(openssl rand -hex 32)" > genesis/node0/key

# Node 1 private key
printf "$(openssl rand -hex 32)" > genesis/node1/key

# Verify they're exactly 64 characters each
wc -c genesis/node0/key genesis/node1/key
```

### Step 4: Generate ENRs (Ethereum Node Records)

```bash
# Generate and save Node 0 ENR (listening on QUIC port 9000)
./zig-out/bin/zeam-tools enrgen --sk $(cat genesis/node0/key) --ip 127.0.0.1 --quic 9000

# Generate and save Node 1 ENR (listening on QUIC port 9001)
./zig-out/bin/zeam-tools enrgen --sk $(cat genesis/node1/key) --ip 127.0.0.1 --quic 9001
```

### Step 5: Create Configuration Files

Create `genesis/config.yaml`:

```yaml
# Genesis Settings
GENESIS_TIME: 1704085200

# Validator Settings  
VALIDATOR_COUNT: 3
```

Create `genesis/nodes.yaml` (paste ENRs from Step 4):

```yaml
- enr:<paste_node0_enr_from_step4>
- enr:<paste_node1_enr_from_step4>
```

Create `genesis/validators.yaml`:

```yaml
zeam_0:
  - 0
zeam_1:
  - 1
  - 2
```

Create `genesis/validator-config.yaml`:

```yaml
shuffle: roundrobin
validators:
  - name: "zeam_0"
    privkey: "$(cat genesis/node0/key)"
    enrFields:
      ip: "127.0.0.1"
      quic: 9000
    count: 1

  - name: "zeam_1"
    privkey: "$(cat genesis/node1/key)"
    enrFields:
      ip: "127.0.0.1"
      quic: 9001
    count: 2
```

### Step 6: Run Node 0 (Terminal 1)

Open a new terminal window and run:

```bash
./zig-out/bin/zeam node \
  --custom_genesis ./genesis \
  --node-id "zeam_0" \
  --validator_config genesis_bootnode \
  --override_genesis_time $GENESIS_TIME \
  --data-dir ./data/test_node0
```

Replace `$GENESIS_TIME` with the actual timestamp from Step 0.

### Step 7: Run Node 1 (Terminal 2)

Open another terminal window and run:

```bash
./zig-out/bin/zeam node \
  --custom_genesis ./genesis \
  --node-id "zeam_1" \
  --validator_config genesis_bootnode \
  --override_genesis_time $GENESIS_TIME \
  --data-dir ./data/test_node1
```

Use the **SAME** `$GENESIS_TIME` value from Step 0.

### Expected Behavior

Both nodes should:

- Start successfully and display the Zeam ASCII logo
- Discover each other as peers
- Begin producing blocks
- Exchange attestations between validators
- Achieve justification and finalization

You'll see output like:

```
Latest Justified:   Slot     12 | Root: 0xc2c1742d996828815b6359a48cb3d404...
Latest Finalized:   Slot      9 | Root: 0xc51a79ed9a8eb78a695639e5599729...
```

## Configuration Details

### Genesis Setup

The fixtures contain a minimal 3-node, 9-validator setup:

**`config.yaml`:**

- `VALIDATOR_COUNT: 9` - Total of 9 validators
- `GENESIS_TIME: 1704085200` - Placeholder (overridden by `--override_genesis_time`)

**`validators.yaml`:**

- `zeam_0: [1, 4, 7]` - zeam_0 controls validator indices 1, 4, and 7
- `quadrivium_0: [2, 5, 8]` - quadrivium_0 controls validator indices 2, 5, and 8  
- `ream_0: [0, 3, 6]` - ream_0 controls validator indices 0, 3, and 6

With 9 validators, we need 2/3 (6 validators) to reach finalization.

**`nodes.yaml`:**

- Contains ENRs (Ethereum Node Records) for network discovery
- Used for peer discovery and connection

**`validator-config.yaml`:**

- Contains node configurations with private keys
- **zeam_0:** Private key and ENR fields for network configuration
- **quadrivium_0:** Private key and ENR fields for network configuration
- **ream_0:** Private key and ENR fields for network configuration

## Recreating the Fixtures

The fixtures are already configured and ready to use. The configuration files contain:

- **Pre-configured private keys** in `validator-config.yaml`
- **Fixed ENRs** for network discovery
- **Validator assignments** for the 9-validator setup

No additional setup is required - you can start using the fixtures immediately with the commands shown above.

## Troubleshooting

### Nodes don't connect to each other

1. Ensure both nodes use the **same** `--override_genesis_time` value
2. Check that ports 9000 and 9001 are not in use: `lsof -i :9000` and `lsof -i :9001`
3. Verify the ENRs in `nodes.yaml` are correct

### "InvalidValidatorConfig" error

- Check that `validators.yaml` node names match the `--node-id` parameter
- Ensure `VALIDATOR_COUNT` in `config.yaml` matches total validators in `validators.yaml`
- Verify that the `node-id` exists in `validator-config.yaml` with a `privkey` field

### Finalization not happening

- You need at least 2/3 validators voting
- With the default setup (9 validators), you need 6 validators to finalize
- Check that both nodes are on the same slot number
- Ensure the `--node-id` values match the entries in `validators.yaml`

### Clean restart

To start fresh:

```bash
rm -rf data/test_node0 data/test_node1
mkdir -p data/test_node0 data/test_node1
# Then run nodes with a new GENESIS_TIME
```

## Important Notes

- **Pre-configured Setup:** All private keys, ENRs, and settings are pre-configured in the YAML files
- **Same Timestamp:** Both nodes MUST use the exact same `--override_genesis_time` value
- **Separate Terminals:** Run each node in its own terminal window to see live output
- **Node IDs:** Use `--node-id` with values from `validators.yaml` (zeam_0, quadrivium_0, ream_0)
- **Data Directories:** Each node needs its own database path to avoid conflicts

## Command Summary

For quick reference, here are the commands assuming `GENESIS_TIME=1759210782`:

**Terminal 1 (zeam_0):**

```bash
./zig-out/bin/zeam node --custom_genesis ./genesis --node-id "zeam_0" --validator_config genesis_bootnode --override_genesis_time 1759210782 --data-dir ./data/test_node0
```

**Terminal 2 (zeam_1):**

```bash
./zig-out/bin/zeam node --custom_genesis ./genesis --node-id "zeam_1" --validator_config genesis_bootnode --override_genesis_time 1759210782 --data-dir ./data/test_node1
```

Replace `1759210782` with your actual `GENESIS_TIME` from `date +%s`.
