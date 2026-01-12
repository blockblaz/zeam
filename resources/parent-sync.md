# Parent Sync

## Steps to Reproduce

1. Build zeam repo & go to the linked lean-quickstart folder in the repo, it is pinned at the zeam_repo branch which is configured to run two zeam instances in binary mode

2. Start the first instance in a terminal:

   ```sh
   NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0 --generateGenesis
   ```

   This will set fresh genesis time and start the node

3. Start the second instance in a new terminal but inside the same lean-quickstart submodule folder:

   ```sh
   NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_1
   ```

   Note that `--generateGenesis` flag is missing so it will use the previously generated genesis data to start the new node

4. Both nodes will peer and advance with finalizations, then stop zeam_1 instance and remove the contents of the folder:

   ```sh
   rm -rf local-devnet/data/zeam_1/*
   ```

5. Restart the zeam_1 using the command in step 3. Then it will peer zeam_0 and get gossip blocks, which will then lead to syncing of the parents and justifications and finality will start again
