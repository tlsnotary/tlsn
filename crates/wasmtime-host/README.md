# Info
This crate builds a wasmtime runtime to be run in Android. The runtime can load and run a wasm component model plugin. UniFFI is used to generate Kotlin bindings and allow the async main function to be driven by Android's async executor.

# Step
Build this crate by running [build.sh](build.sh). The build script assumes the following to be available.
- `aarch64-linux-android` rust target
- [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk)
- [`androidwasmtime`](https://github.com/tlsnotary/androidwasmtime) on the same directory level as this repo