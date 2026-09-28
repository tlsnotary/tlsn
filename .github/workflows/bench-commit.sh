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

  # Browser teardown (non-fatal). The harness's own shutdown is
  # best-effort (5s cap, and it only reaps the `sudo` wrapper, not Chrome), so
  # kill any leftover harness Chrome and verify it is gone. Never fails.
  if [[ "$target" == "browser" ]]; then
    report="$RESULTS_DIR/browser-teardown.txt"
    pat='--user-data-dir=/tmp/tmp\.'
    if pgrep -f -- "$pat" >/dev/null 2>&1; then
      echo "[$(date -u +%T)] leftover after ${LABEL}/browser/${config}; killing + verifying" >> "$report" || true
      pgrep -af -- "$pat" >> "$report" || true
      pkill -KILL -f -- "$pat" 2>/dev/null || true
      deadline=$((SECONDS + 10))
      while pgrep -f -- "$pat" >/dev/null 2>&1 && [[ "$SECONDS" -lt "$deadline" ]]; do sleep 1; done
      if pgrep -f -- "$pat" >/dev/null 2>&1; then
        echo "[$(date -u +%T)] STILL ALIVE after kill (${LABEL}/browser/${config}):" >> "$report" || true
        pgrep -af -- "$pat" >> "$report" || true
        for p in $(pgrep -f -- "$pat"); do
          printf '  pid %s state %s\n' "$p" "$(awk '{print $3}' /proc/$p/stat 2>/dev/null)" >> "$report" || true
        done
        echo "::warning::chrome survived kill after ${LABEL}/browser/${config} (see browser-teardown.txt)"
      else
        echo "[$(date -u +%T)] killed+confirmed clean after ${LABEL}/browser/${config}" >> "$report" || true
      fi
    else
      echo "[$(date -u +%T)] clean after ${LABEL}/browser/${config}" >> "$report" || true
    fi
  fi
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
