## Interactive Predicate: Proving Predicates over Transcript Data

This example demonstrates how to use TLSNotary to prove predicates (boolean constraints) over transcript bytes in zero knowledge, without revealing the actual data.

In this example:
- The server returns JSON data containing a "name" field with a string value
- The Prover proves that the name value is a valid JSON string without revealing it
- The Verifier learns that the string is valid JSON, but not the actual content

This uses `mpz_predicate` to build predicates that operate on transcript bytes. The predicate is compiled to a circuit and executed in the ZK VM to prove satisfaction.

### Running the Example

First, start the test server from the root of this repository:
```shell
RUST_LOG=info PORT=4000 cargo run --bin tlsn-server-fixture
```

Next, run the interactive predicate example:
```shell
SERVER_PORT=4000 cargo run --release --example interactive_predicate
```

To view more detailed debug information:
```shell
RUST_LOG=debug,yamux=info,uid_mux=info SERVER_PORT=4000 cargo run --release --example interactive_predicate
```

> Note: In this example, the Prover and Verifier run on the same machine. In real-world scenarios, they would typically operate on separate machines.
