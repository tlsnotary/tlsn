<p align="center">
    <img src="./tlsn-banner.png" width=1280 />
</p>

![MIT licensed][mit-badge]
![Apache licensed][apache-badge]
[![Build Status][actions-badge]][actions-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[apache-badge]: https://img.shields.io/github/license/saltstack/salt
[actions-badge]: https://github.com/tlsnotary/tlsn/actions/workflows/ci.yml/badge.svg
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

- [tlsn](./tlsn/): The home for examples and API libraries.
    - [examples](./tlsn/examples/): Examples on how to use the TLSNotary protocol.
    - [tlsn-prover](./tlsn/tlsn-prover/): The library for the prover component.
    - [tlsn-verifier](./tlsn/tlsn-verifier/): The library for the verifier component.
- [notary](./notary/): Implements the [notary server](https://docs.tlsnotary.org/intro.html#tls-verification-with-a-general-purpose-notary) and its client.
- [components](./components/): Houses low-level libraries utilized by [tlsn](./tlsn/).

This repository contains the source code for the Rust implementation of the TLSNotary protocol. For additional tools and implementations related to TLSNotary, visit <https://github.com/tlsnotary>. This includes repositories such as [`tlsn-js`](https://github.com/tlsnotary/tlsn-js), [`tlsn-extension`](https://github.com/tlsnotary/tlsn-extension), [`explorer`](https://github.com/tlsnotary/explorer), among others.


## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

See [CONTRIBUTING.md](CONTRIBUTING.md).
