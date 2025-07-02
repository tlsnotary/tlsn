# TLSNotary Harness

A harness for testing and benchmarking the TLSNotary protocol with both native and browser support.

## Installation

The harness requires the nightly compiler to build the WASM binary. Additionally, we depend on a specific
version of `wasm-pack` which must be installed:

```bash
cargo install --git https://github.com/rustwasm/wasm-pack.git --rev 32e52ca
```

## Getting started

First build the harness.

```sh
./build.sh
```

With the harness built, run the following to see the available commands and options in the harness CLI.

```sh
./bin/runner --help
```

## Network setup

Running the harness requires root privileges to be able to set up a virtual network. Before running tests or benchmarks, first
set up the network.

```sh
sudo ./bin/runner setup
```

This network can be torn down simply by running:

```sh
sudo ./bin/runner clean
```

## Tests

See the CLI manual for available testing options.

To add new tests, one can register a test in the [plugin directory](executor/test_plugins).

See existing tests for an example of how to do so.

## Benches

See the CLI manual for available benching options.

To add or modify benchmarks, see the [`bench.toml`](bench.toml) file.

## Browser

The harness supports running tests and benches in the browser by setting the `--target browser` flag in the cli.