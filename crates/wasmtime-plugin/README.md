# Info
This crate builds a wasm component model plugin. It has an async main function that calls some host functions.

# Step
1. Build this crate by running [build.sh](build.sh). The build script assumes the following to be available.
- `wasm32-unknown-unknown` rust target
- [`wasm-tools`](https://github.com/bytecodealliance/wasm-tools)
2. Drag and drop the `wasmtime_plugin_component.wasm` built into Xcode.