## Simple Interactive Verifier: Verifying Data from an API in Rust

This example demonstrates how to use TLSNotary in a simple interactive session between a Prover and a Verifier. It involves the Verifier first verifying the MPC-TLS session and then confirming the correctness of the data.

This example fetches data from a local test server. To start this server, run:
```shell
RUST_LOG=info PORT=4000 cargo run --bin tlsn-server-fixture
```
Next, run the interactive example with:
```shell
SERVER_PORT=4000 cargo run --release --example interactive
```
To view more detailed debug information, use the following command:
```
RUST_LOG=debug,yamux=info,uid_mux=info SERVER_PORT=4000 cargo run --release --example interactive
```

> ℹ️ Note: In this example, the Prover and Verifier run on the same machine. In real-world scenarios, the Prover and Verifier would typically operate on separate machines.