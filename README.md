<p align="center">
    <img src="./tlsn-banner.png" width=1280 />
</p>

![MIT licensed][mit-badge]
![Apache licensed][apache-badge]
[![Build Status][actions-badge]][actions-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[apache-badge]: https://img.shields.io/github/license/saltstack/salt
[actions-badge]: https://github.com/tlsnotary/tlsn/actions/workflows/ci.yml/badge.svg?branch=dev
[actions-url]: https://github.com/tlsnotary/tlsn/actions?query=workflow%3Aci+branch%3Adev

[Website](https://tlsnotary.org) |
[Documentation](https://docs.tlsnotary.org) |
[API Docs](https://tlsnotary.github.io/tlsn) |
[Discord](https://discord.gg/9XwESXtcN7)

# TLSNotary

**Data provenance and privacy with secure multi-party computation**

## ⚠️ Notice

This project is currently under active development and should not be used in production. Expect bugs and regular major breaking changes.

## License
All crates in this repository are licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Branches

- [`main`](https://github.com/tlsnotary/tlsn/tree/main)
  - Default branch — points to the latest release.
  - This is stable and suitable for most users.
- [`dev`](https://github.com/tlsnotary/tlsn/tree/dev)
  - Development branch — contains the latest PRs.
  - Developers should submit their PRs against this branch.

## Directory

- [examples](./crates/examples/): Examples on how to use the TLSNotary protocol.
- [tlsn-prover](./crates/prover/): The library for the prover component.
- [tlsn-verifier](./crates/verifier/): The library for the verifier component.
- [notary](./crates/notary/): Implements the [notary server](https://docs.tlsnotary.org/intro.html#tls-verification-with-a-general-purpose-notary) and its client.
- [components](./crates/components/): Houses low-level libraries.

This repository contains the source code for the Rust implementation of the TLSNotary protocol. For additional tools and implementations related to TLSNotary, visit <https://github.com/tlsnotary>. This includes repositories such as [`tlsn-js`](https://github.com/tlsnotary/tlsn-js), [`tlsn-extension`](https://github.com/tlsnotary/tlsn-extension), [`explorer`](https://github.com/tlsnotary/explorer), among others.


## Development

> [!IMPORTANT]
> **Note on Rust-to-WASM Compilation**: This project requires compiling Rust into WASM, which needs [`clang`](https://clang.llvm.org/) version 16.0.0 or newer. MacOS users, be aware that Xcode's default `clang` might be older. If you encounter the error `No available targets are compatible with triple "wasm32-unknown-unknown"`, it's likely due to an outdated `clang`. Updating `clang` to a newer version should resolve this issue.
> 
> For MacOS aarch64 users, if Apple's default `clang` isn't working, try installing `llvm` via Homebrew (`brew install llvm`). You can then prioritize the Homebrew `clang` over the default macOS version by modifying your `PATH`. Add the following line to your shell configuration file (e.g., `.bashrc`, `.zshrc`):
> ```sh
> export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
> ```

If you run into this error:
```
Could not find directory of OpenSSL installation, and this `-sys` crate cannot
  proceed without this knowledge. If OpenSSL is installed and this crate had
  trouble finding it,  you can set the `OPENSSL_DIR` environment variable for the
  compilation process.
```
Make sure you have the development packages of OpenSSL installed (`libssl-dev` on Ubuntu or `openssl-devel` on Fedora).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

See [CONTRIBUTING.md](CONTRIBUTING.md).
