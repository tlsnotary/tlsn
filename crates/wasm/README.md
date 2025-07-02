# TLSNotary WASM Bindings

This crate provides a WebAssembly package for TLSNotary, offering core functionality for the TLSNotary attestation protocol along with useful TypeScript types.

For most use cases, you may prefer to use the `tlsn-js` package instead: [tlsn-js on npm](https://www.npmjs.com/package/tlsn-js).

## Dependencies

A specific version of `wasm-pack` must be installed to build the WASM binary:

```bash
cargo install --git https://github.com/rustwasm/wasm-pack.git --rev 32e52ca
```

## Links

- [Website](https://tlsnotary.org)
- [Documentation](https://docs.tlsnotary.org)
- [API Docs](https://tlsnotary.github.io/tlsn)