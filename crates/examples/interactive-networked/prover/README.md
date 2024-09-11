## Interactive Prover
An implementation of the interactive prover in Rust.

## Running the prover
1. Configure this prover setting via the global variables defined in [main.rs](./src/main.rs) — please ensure that the hardcoded `SERVER_URL` and `VERIFICATION_SESSION_ID` have the same values on the verifier side.
2. Start the prover by running the following in a terminal at the root of this crate.
```bash
cargo run --release
```
