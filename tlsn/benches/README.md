# TLSNotary bench utilities

This crate provides utilities for benchmarking protocol performance under various network conditions and usage patterns.

As the protocol is mostly IO bound, it's important to track how it performs in low bandwidth and/or high latency environments. To do this we set up temporary network namespaces and add virtual ethernet interfaces which we can control using the linux `tc` (Traffic Control) utility.

## Configuration

See the `bench.toml` file for benchmark configurations.

## Preliminaries

To run the benchmarks you will need `iproute2` installed, eg:
```sh
sudo apt-get install iproute2 -y
```

## Running benches

Running the benches requires root privileges because they will set up virtual interfaces. The script is designed to fully clean up when the benches are done, but run them at your own risk.

Make sure you're in the `tlsn/benches/` directory, build the binaries then run the script:

```sh
cargo build --release
sudo ./bench.sh
```

## Metrics

After you run the benches you will see a `metrics.csv` file in the working directory. It will be owned by `root`, so you probably want to run

```sh
sudo chown $USER metrics.csv
```