# lean quickstart

A single command line quickstart to spin up lean node(s)

## Requirements

1. Shell terminal: Preferably linux especially if you want to pop out separate new terminals for node
2. Genesis configuration
3. Zeam Build (other clients to be supported soon)

## Scenarios

### Quickly startup two zeam nodes as a local devnet

```sh
NETWORK_DIR=local-devnet ./spin-node.sh --node all --freshStart
```
  
## Args

1. `NETWORK_DIR` is an env to specify the network directory. Should have a `genesis` directory with genesis config. A `data` folder will be created inside this `NETWORK_DIR` if not already there.
  `genesis` directory should have the following files

    a. `validator_config.yaml` which has node setup information for all the bootnodes
    b. `validators.yaml` which assigns validator indices
    c. `nodes.yaml` which has the enrs generated for each of the respective nodes.
    d. `config.yaml` the actual network config

2. `--freshStart` reset the genesis time in the `config.yaml` to now
3. `--inTerminal` if you don't want to pop out new terminals to run the nodes, else by default opens gnome terminals
4. `--node` specify which node you want to run, use `all` to run all the nodes in a single go, otherwise you may specify which node you want to run from `validator_config.yaml`. 
  The client is provided this input so as to parse the correct node configuration to startup the node.
5. `--validatorConfig` is the path to specify your nodes `validator_config.yaml`, `validators.yaml` (for which `--node` is still the node key to index) if your node is not a bootnode. 
  If unspecified it assumes value of `genesis_bootnode` which is to say that your node config is to be picked from `genesis` folder with `--node` as the node key index.
  This value is further provided to the client so that they can parse the correct config information.