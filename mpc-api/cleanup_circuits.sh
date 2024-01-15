#!/bin/bash

# This script is used to clean up the circuits created by the MPC API.
# Deletes all the directories in the MPC API directory that start with "circuit_"

# Get the directory of the MPC API
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Delete all the directories that start with "circuit_" an
rm -rf $DIR/circuit_*
