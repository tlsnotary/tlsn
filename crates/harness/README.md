# TLSNotary Harness

This package provides a harness for testing and benchmarking the TLSNotary protocol with both native and browser support.

## Getting started

Run the following to see the available commands and options in the harness CLI.

```sh
cargo run --release -- --help
```

## Tests

See the CLI manual for available testing options.

To add new tests, one can simply register a test anywhere in the harness source code (preferably within the tests module).

See [existing tests](src/tests.rs) as an example.

```rust
test!("test_basic", test_prover, test_verifier);
```

## Benches

See the CLI manual for available benching options.

To add or modify benchmarks, see the [`bench.toml`](bench.toml) file.

