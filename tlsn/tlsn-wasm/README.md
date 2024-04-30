# TLSNotary WASM bindings

## Build

To build or package the WASM bindings, run the provided scripts:

| action            | script         |
| ----------------- | -------------- |
| build only        | `./build.sh`   |
| build and package | `./package.sh` |

Note that this crate must be built using the nightly version of the Rust compiler because it utilizes features from [`wasm-bindgen-rayon`](https://docs.rs/wasm-bindgen-rayon/latest/wasm_bindgen_rayon/#building-rust-code).
