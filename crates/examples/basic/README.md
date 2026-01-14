## Simple Basic Verifier: Verifying Data from an API in Rust

This example demonstrates how to use TLSNotary in a simple session between a Prover and a Verifier.

This example fetches data from a local test server. To start the server, run the following command from the root of this repository (not from this example's folder):
```shell
RUST_LOG=info PORT=4000 cargo run --bin tlsn-server-fixture
```
Next, run the basic example with:
```shell
SERVER_PORT=4000 cargo run --release --example basic
```
To view more detailed debug information, use the following command:
```
RUST_LOG=debug,yamux=info,uid_mux=info SERVER_PORT=4000 cargo run --release --example basic
```

> ℹ️ Note: In this example, the Prover and Verifier run on the same machine. In real-world scenarios, the Prover and Verifier would typically operate on separate machines.
