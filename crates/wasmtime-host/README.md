
# Info
This crate builds a wasmtime binary to be run in iOS. The binary loads and run a wasm component model plugin. UniFFI is used to generate Swift bindings and allow the binary's future to be driven by iOS' async executor.

# Step
1. Build this crate by running [build.sh](build.sh). The build script assumes the following to be available.
- `aarch64-apple-ios-sim`, `aarch64-apple-ios` rust targets
- `xcodebuild` CLI tool
2. Drag and drop the `wasmtime_host.xcframework/`, `uniffi/` built into Xcode.
