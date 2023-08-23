This guide will take you through the steps of:
- starting a `Notary` server
- running a `Prover` to notarize some web data
- running a `Verifier` to verify the notarized data

Note that the TLSNotary protocol assumes that the `Notary` is trusted by the `Verifier`. To minimize the trust, the `Verifier` itself can act as a `Notary`.

# Preliminaries

### Install rust

If you don't have `rust` installed yet, install it with [rustup](https://rustup.rs/):
```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

# Guide

### Start a Notary server:

```shell
git clone https://github.com/tlsnotary/notary-server
cd notary-server
cargo run --release
```

The `Notary` server will now be running in the background waiting for connections from a `Prover`. You can switch to another console to run the `Prover`.

For more information on how to configure the `Notary` server, please refer to [this](https://github.com/tlsnotary/notary-server#running-the-server).

### Run a simple Prover:

```shell
git clone https://github.com/tlsnotary/tlsn
cd tlsn/tlsn/examples
cargo run --release --example simple_prover
```

The notarization session usually takes a few moments and the resulting proof will be written to the "proof.json" file. The proof can then be passed on to the `Verifier` for verification.

The `simple_prover` notarizes <https://example.com> and redacts the `USER_AGENT` HTTP header from the proof for the `Verifier`. You can change the code in `tlsn/tlsn/examples/simple_prover.rs` to meet your needs:

- change which server the `Prover` connects to
- add or remove HTTP request headers
- redact other strings in the request or the response

⚠️ Please note that by default the `Notary` server expects that the cumulative size of the request and the server response is not more than 16KB.


### Run a simple Verifier:

```shell
cargo run --release --example simple_verifier
```

This will verify the proof from the `simple_prover` (`proof.json`) and output the result to the console.

Note how the parts which the prover chose not to disclose will be shown as "X":
```plaintext
GET / HTTP/1.1
host: example.com
accept: */*
accept-encoding: identity
connection: close
user-agent: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```