# Interactive Verifier: Verifying Data from an API in Rust

This example demonstrates how to use TLSNotary in a simple interactive session between a Prover and a Verifier. It involves the Verifier first verifying the MPC-TLS session and then confirming the correctness of the data.

In this example, the Verifier connects to <https://swapi.dev> and proves data to the verifier.

# Run example on a single computer

You can run both the verifier and prover with:
```sh
cargo run -release --example interactive_networked
```

# Run example on two different computers

To run the example on two different computers, start the verifier first on machine 1:
```sh
cd verifier
cargo run --release
```
Note: make sure port `9816` is open if you run a firewall.

Next, on machine 2:
1. Update the (ip address of the verifier on machine 1)[file:./prover/src/main.rs]
2. Run:
```sh
cd prover
cargo run --release
```
