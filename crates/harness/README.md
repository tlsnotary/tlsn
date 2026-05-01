# TLSNotary Harness

A harness for testing and benchmarking the TLSNotary protocol with both native and browser support.

## Installation

The harness requires the nightly compiler to build the WASM binary. Additionally, `wasm-pack` 0.14.0+
must be installed (for custom profile support):

```bash
cargo install wasm-pack
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

## Troubleshooting

### Browser harness hangs with no progress

If the harness hangs when using `--target browser`, it is likely a firewall issue. In browser mode, Chrome connects to WebSocket proxies bound to the host's bridge IP. This traffic hits the host's INPUT chain, where firewalls with a default-drop policy silently block it. Native mode is unaffected because it connects directly between namespaces (FORWARD chain).

Fix: allow traffic on the bridge interface before running the harness:

```sh
sudo iptables -I INPUT -i tlsn-br -j ACCEPT
```

Or temporarily stop the firewall:

```sh
# systemd-based (NixOS, Fedora, etc.)
sudo systemctl stop firewall.service

# ufw (Ubuntu, Debian)
sudo ufw disable
```
