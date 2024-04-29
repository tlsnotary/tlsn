# TLSNotary WASM bindings

## Build

This crate must be built using the nightly rust compiler with the following flags:

```bash
RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals" \
rustup run nightly  \
wasm-pack build --target web . -Z build-std=panic_abort,std
```


