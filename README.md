<p align="center">
    <img src="./tlsn-banner.png" width=1280 />
</p>

# TLSNotary

## ⚠️ Notice

This project is currently under active development and should not be used in production. Expect bugs and regular major breaking changes.

## License
All crates in this repository are licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Useful Links
- website: <https://tlsnotary.org/>
- rust codebase: <https://github.com/tlsnotary/tlsn>
- documentation: <https://docs.tlsnotary.org/protocol/notarization/index.html> (under development)

## Overview
- **mpc**: Home of multi-party computation libraries
    - oblivious transfer: Core building block used a lot in our codebase.
    - garbling: We use several variants of garbled circuit executions in our codebase
      (DEAP, Dual-Ex, ZK)
    - circuits: code to build circuits, which can be used in a garbling scheme.
      Also contains some hard-coded circuits.
    - share-conversion: Allows to convert different sharing schemes of field elements
      into each other using oblivious transfer.
- **tls**: Home of the TLS logic of our protocol like handshake en-/decryption, ghash, **currently outdated**
- **utils**: Utility functions which are frequently used everywhere
- **actors**: Provides actors, which implement protocol-specific functionality using
  the actor pattern. They usually wrap an aio module
- **universal-hash**: Implements ghash, which is used AES-GCM. Will probably also
  implement Poly-1305 at some later point.
- **point-addition**: Used in key-exchange and allows to compute a two party sharing of
  an EC curve point

### General remarks

- the TLSNotary codebase makes heavy use of async Rust. Usually an aio
  crate/module implements the network IO and wraps a core crate/module which
  provides the protocol implementation. This is a frequent pattern you will
  encounter in the codebase.
- when a sub-protocol is used in many places (like e.g. Oblivious Transfer) we
  usually have an actor to simplify passing around instances of this sub-protocol

