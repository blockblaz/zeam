# Checkpoint Sync

Checkpoint sync allows a new node to quickly synchronize by downloading the finalized state from a trusted peer instead of syncing from genesis.

## Prerequisites

- Build zeam repo
- Go to the linked lean-quickstart folder in the repo (pinned at the zeam_repo branch)

## Steps to Reproduce

1. Start the first instance in a terminal:

   ```sh
   NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0 --generateGenesis
   ```

   This will set fresh genesis time and start the node. Wait for a few slots to allow finalization to occur.

2. Verify the first node has finalized state by checking its API:

   ```sh
   curl -s http://localhost:9667/lean/v0/states/finalized -o /dev/null -w "%{http_code}\n"
   ```

   You should see `200` once the node has finalized state available.

3. Start the second instance in a new terminal with checkpoint sync enabled:

   ```sh
   NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_1 --checkpointSyncUrl http://localhost:9667
   ```

   The second node will:
   - Download the finalized state from zeam_0's API endpoint (`/lean/v0/states/finalized`)
   - Verify the state matches the expected genesis configuration (validator count)
   - Use this state as its anchor to sync forward

4. Observe the logs on zeam_1. You should see messages like:

   ```
   checkpoint sync enabled, downloading state from: http://localhost:9667/lean/v0/states/finalized
   checkpoint state verified: slot=X, validators=N, state_root=0x..., block_root=0x...
   checkpoint sync completed successfully, using state at slot X as anchor
   ```

5. Both nodes will peer and continue advancing with finalizations.

## Testing Checkpoint Sync Failure Fallback

To test the fallback behavior when checkpoint sync fails:

1. Start zeam_1 with an invalid checkpoint URL:

   ```sh
   NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_1 --checkpointSyncUrl http://localhost:9999
   ```

2. The node should log a warning and fall back to loading from database or genesis:

   ```
   checkpoint sync failed: ..., falling back to database/genesis
   ```

## API Endpoint

The checkpoint sync feature uses the `/lean/v0/states/finalized` endpoint which returns:
- **Content-Type**: `application/octet-stream`
- **Body**: SSZ-encoded `BeamState`
- **Status 503**: Returned if no finalized state is available yet
