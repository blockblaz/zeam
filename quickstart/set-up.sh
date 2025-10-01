#!/bin/bash
# set -e

mkdir $dataDir

for item in "${spin_nodes[@]}"; do
  itemDataDir="$dataDir/$item"
  mkdir $itemDataDir
  cmd="rm -rf $itemDataDir/*"
  # always show the executing command
  echo $cmd
  eval $cmd
done;

if [ -n "$freshStart" ]
then
  TIME_NOW="$(date +%s)"
  GENESIS_TIME=$((TIME_NOW))
  sedPatten="/GENESIS_TIME/c\GENESIS_TIME: $GENESIS_TIME"
  cmd="sed -i \"$sedPatten\" \"$configDir/config.yaml\""
  echo $cmd
  eval $cmd
fi;
