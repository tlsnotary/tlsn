# Info
This crate builds a wasm component model plugin. It has an async main function that calls some host functions.

# Step
Build this crate by running [build.sh](build.sh). The build script assumes the following to be available.
- `wasm32-unknown-unknown` rust target
- [`wasm-tools`](https://github.com/bytecodealliance/wasm-tools)
- [`androidwasmtime`](https://github.com/tlsnotary/androidwasmtime) on the same directory level as this repo