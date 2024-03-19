#! /bin/bash

# Check if we are running as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root"
  exit
fi

# Run the benchmark binary
../target/release/bench

# Plot the results
../target/release/plot metrics.csv
