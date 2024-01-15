#!/bin/bash

# Path to the top-level Cargo.toml
CARGO_TOML="Cargo.toml"

# Extract project paths from the Cargo.toml file
PROJECT_DIRS=$(grep -A 1 "\[workspace\]" $CARGO_TOML | grep -v "\[workspace\]" | grep -v "]" | sed 's/"//g' | sed 's/,//g' | sed 's/ //g')

# Check if any directories are found
if [ -z "$PROJECT_DIRS" ]; then
    echo "No project directories found in $CARGO_TOML"
    exit 1
fi

# Iterate through each directory and run cargo clean
for dir in $PROJECT_DIRS; do
    if [ -d "$dir" ]; then
        echo "Cleaning project in $dir..."
        (cd "$dir" && cargo clean)
    else
        echo "Warning: Directory $dir does not exist"
    fi
done

echo "All projects cleaned."
