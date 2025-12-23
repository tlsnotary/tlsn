# TLSNotary Benchmark Plot Tool

Generates interactive HTML and SVG plots from TLSNotary benchmark results. Supports comparing multiple benchmark runs (e.g., before/after optimization, native vs browser).

## Usage

```bash
tlsn-harness-plot <TOML> <CSV>... [OPTIONS]
```

### Arguments

- `<TOML>` - Path to Bench.toml file defining benchmark structure
- `<CSV>...` - One or more CSV files with benchmark results

### Options

- `-l, --labels <LABEL>...` - Labels for each dataset (optional)
  - If omitted, datasets are labeled "Dataset 1", "Dataset 2", etc.
  - Number of labels must match number of CSV files
- `--min-max-band` - Add min/max bands to plots showing variance
- `-h, --help` - Print help information

## Examples

### Single Dataset

```bash
tlsn-harness-plot bench.toml results.csv
```

Generates plots from a single benchmark run.

### Compare Two Runs

```bash
tlsn-harness-plot bench.toml before.csv after.csv \
  --labels "Before Optimization" "After Optimization"
```

Overlays two datasets to compare performance improvements.

### Multiple Datasets

```bash
tlsn-harness-plot bench.toml native.csv browser.csv wasm.csv \
  --labels "Native" "Browser" "WASM"
```

Compare three different runtime environments.

### With Min/Max Bands

```bash
tlsn-harness-plot bench.toml run1.csv run2.csv \
  --labels "Config A" "Config B" \
  --min-max-band
```

Shows variance ranges for each dataset.

## Output Files

The tool generates two files per benchmark group:

- `<output>.html` - Interactive HTML chart (zoomable, hoverable)
- `<output>.svg` - Static SVG image for documentation

Default output filenames:
- `runtime_vs_bandwidth.{html,svg}` - When `protocol_latency` is defined in group
- `runtime_vs_latency.{html,svg}` - When `bandwidth` is defined in group

## Plot Format

Each dataset displays:
- **Solid line** - Total runtime (preprocessing + online phase)
- **Dashed line** - Online phase only
- **Shaded area** (optional) - Min/max variance bands

Different datasets automatically use distinct colors for easy comparison.

## CSV Format

Expected columns in each CSV file:
- `group` - Benchmark group name (must match TOML)
- `bandwidth` - Network bandwidth in Kbps (for bandwidth plots)
- `latency` - Network latency in ms (for latency plots)
- `time_preprocess` - Preprocessing time in ms
- `time_online` - Online phase time in ms
- `time_total` - Total runtime in ms

## TOML Format

The benchmark TOML file defines groups with either:

```toml
[[group]]
name = "my_benchmark"
protocol_latency = 50  # Fixed latency for bandwidth plots
# OR
bandwidth = 10000      # Fixed bandwidth for latency plots
```

All datasets must use the same TOML file to ensure consistent benchmark structure.

## Tips

- Use descriptive labels to make plots self-documenting
- Keep CSV files from the same benchmark configuration for valid comparisons
- Min/max bands are useful for showing stability but can clutter plots with many datasets
- Interactive HTML plots support zooming and hovering for detailed values
