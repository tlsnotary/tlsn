# TLSNotary WASM Bindings

This crate provides a WebAssembly package for TLSNotary, offering core functionality for the TLSNotary attestation protocol along with useful TypeScript types.

For browser usage, check the [`tlsn-extension`](https://github.com/tlsnotary/tlsn-extension) mono-repo.

## Dependencies

`wasm-pack` 0.14.0+ must be installed to build the WASM binary (for custom profile support):

```bash
cargo install wasm-pack
```

## Releasing to npm

Releases are published manually. CI builds and uploads a `tlsn-wasm` package
artifact on every tagged build (see `ci.yml`); `publish.sh` downloads that
artifact and pushes it to npm.

One-time setup:

1. Be a maintainer of [`tlsn-wasm`](https://www.npmjs.com/package/tlsn-wasm) on
   npm.
2. Authenticate locally:
   - `gh auth login` (needs read access to `tlsnotary/tlsn` Actions artifacts)
   - `npm login` — verify with `npm whoami`. 2FA OTP is prompted at publish
     time.

To publish a tag (after the CI run for that tag has completed successfully):

```bash
./publish.sh v0.1.0-alpha.16
```

The script shows a `npm publish --dry-run` and asks for confirmation before
actually publishing. Pass a second argument to use a non-`latest` dist-tag,
e.g. `./publish.sh v0.1.0-alpha.16 alpha`.

## Links

- [Website](https://tlsnotary.org)
- [Documentation](https://docs.tlsnotary.org)
- [API Docs](https://tlsnotary.github.io/tlsn)