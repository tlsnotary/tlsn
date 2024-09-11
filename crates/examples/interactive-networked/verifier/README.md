# verifier-server

An implementation of the interactive verifier server in Rust.

## Running the server
1. Configure this server setting via the global variables defined in [main.rs](./src/main.rs) — please ensure that the hardcoded `SERVER_DOMAIN` and `VERIFICATION_SESSION_ID` have the same values on the prover side.
2. Start the server by running the following in a terminal at the root of this crate.
```bash
cargo run --release
```

## WebSocket APIs
### /verify
To perform verification via websocket, i.e. `ws://localhost:9816/verify`
