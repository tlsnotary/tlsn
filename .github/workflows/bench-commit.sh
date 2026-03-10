#!/usr/bin/env bash
#
# Build and benchmark a single commit checkout.
#
# Usage: bench-commit.sh <label> <mode>
#
#   label   identifier used for output filenames (e.g. commit1, commit2)
#   mode    "quick" (3 samples, bench.toml only) or "precise" (5 samples + sweeps)
#
# Must be run from the harness directory (e.g. tlsn-commit1/crates/harness).
# Outputs CSV files to /tmp/benchmark-results/<label>-<target>-<config>.csv

set -euo pipefail

LABEL="$1"
MODE="$2"

RESULTS_DIR="/tmp/benchmark-results"
mkdir -p "$RESULTS_DIR"

if [[ "$MODE" == "quick" ]]; then
  SAMPLES_ARGS="--samples 3 --samples-override"
else
  SAMPLES_ARGS="--samples 5 --samples-override"
fi

# --- Build ------------------------------------------------------
echo "=== Building harness ==="
chmod +x build.sh
./build.sh

# --- Setup network ----------------------------------------------
echo "=== Setting up network ==="
sudo ./bin/runner setup

# --- Benchmarks -------------------------------------------------
run_bench() {
  local target="$1"
  local config="$2"
  local samples_args="$3"
  local target_flag=""

  if [[ "$target" == "browser" ]]; then
    target_flag="--target browser"
  fi

  # shellcheck disable=SC2086
  ./bin/runner $target_flag bench --config "$config" $samples_args
  cp metrics.csv "${RESULTS_DIR}/${LABEL}-${target}-${config%.toml}.csv"
}

for target in native browser; do
  echo "=== Running ${target} benchmarks ==="
  run_bench "$target" bench.toml "$SAMPLES_ARGS"

  if [[ "$MODE" == "precise" ]]; then
    for config in bench_bandwidth_sweep.toml bench_latency_sweep.toml bench_download_sweep.toml; do
      echo "=== Running ${target} ${config} ==="
      run_bench "$target" "$config" "--samples 5 --samples-override"
    done
  fi
done
