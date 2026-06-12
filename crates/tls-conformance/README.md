# tlsn-tls-conformance

TLS **client** conformance testing for TLSNotary, using
[BoGo](https://boringssl.googlesource.com/boringssl/+/master/ssl/test/) — the
TLS protocol test suite from BoringSSL. This is the same suite (and integration
model) that [rustls](https://github.com/rustls/rustls/tree/main/bogo) uses.

## How it works

BoGo splits into two halves:

- **The runner** (Go) — a heavily-instrumented TLS peer plus thousands of test
  cases. When testing a *client*, it acts as the TLS **server**. We use the
  pinned `rustls/boringssl` snapshot and build it as a standalone binary; it is
  only ever a test-time dependency (never built or linked into TLSNotary).
- **The shim** (`src/bin/bogo_shim.rs`, Rust) — the adapter we own. For each
  test the runner launches the shim with flags describing the scenario; the shim
  connects back over TCP and drives a TLS handshake with the library under test,
  reporting the result via its exit code (`0` ok, `89` unimplemented/skip, other
  = failure).

TLSNotary's "client" is two parties — a **prover** and a **verifier** running an
MPC-TLS protocol. The shim runs both in-process (wired over an in-memory
duplex), with the prover connecting to the runner as the server peer.

```
            BoGo runner (Go)  ── TLS server peer
                  ▲  TCP
                  │
      ┌───────────┴───────────┐  prover.connect(server_socket = TCP)
      │   prover  ⇄  verifier  │  ← MPC-TLS (in-memory duplex between them)
      └───────────────────────┘
              the shim
```

A third piece, the **orchestrator** (`src/bin/bogo.rs`), builds the runner
(`bogo fetch`) and drives the suite (`bogo run`). The reusable shim logic lives
in the crate library (`src/lib.rs`); `src/flags.rs` holds the BoGo flag
vocabulary.

## Scope

BoGo tests the **TLS protocol**; TLSNotary's attestation/disclosure phase is out
of scope. The shim runs only the handshake and record-layer exchange (prover
`connect` + future; verifier `commit` → `run`) and stops — it never calls
`prove`/`verify`. Note the MPC client *does* verify the server certificate's
**name** during the handshake (so the shim's server name must match the runner's
cert, which has SAN `test`); only chain-of-trust validation is deferred to the
skipped prove phase.

TLSNotary's MPC-TLS currently supports a narrow surface: **TLS 1.2** with the
two `ECDHE_{RSA,ECDSA}_WITH_AES_128_GCM_SHA256` cipher suites and client
authentication (the prover signs `CertificateVerify` with its own key); no
TLS 1.3, no resumption, no renegotiation. Most BoGo tests exercise features
outside this surface and are reported as unimplemented (`89`).

This crate is currently a **completeness harness** — it wires up the full suite
and reports the runner's results. Many tests are expected to be skipped or to
fail; we do not yet gate CI on a green suite. The main levers for improving the
pass/skip/fail split over time:

- `parse()` in `src/lib.rs` (and `UNSUPPORTED_FLAGS` in `src/flags.rs`) — which
  flags map to "skip" (`89`) vs "run and maybe fail".
- `bogo/config.json` — `DisabledTests` (pattern → reason) and `ErrorMap`
  (runner error → our error string) so expected-failure tests can match.

## Usage

Everything is driven by the `bogo` binary.

Build the Go runner once (requires `go` and `git`):

```sh
cargo run -p tlsn-tls-conformance --bin bogo -- fetch
```

Run the whole suite (builds the shim for you, tallies results, exits non-zero if
any test failed):

```sh
cargo run -p tlsn-tls-conformance --bin bogo -- run
```

Run a subset — selectors are `filepath.Match` globs:

```sh
cargo run -p tlsn-tls-conformance --bin bogo -- run 'VersionNegotiation-Client-TLS12-*'
cargo run -p tlsn-tls-conformance --bin bogo -- run --workers 1 'MinimumVersion-Client-*'
```

> **Parallelism.** Each shim runs a full multi-threaded MPC executor (one thread
> per core, plus rayon). Running many shims at once oversubscribes the CPU and
> handshakes start missing the runner's per-connection timeout. The orchestrator
> defaults to 2 workers (`--workers N` to override). Combined with a full 2PC
> handshake per test, the suite is slow; scope runs with a glob while iterating.

> Set `BOGO_NYI_LOG=/path/to/log` to have the shim record *why* each skipped
> test was skipped (one reason per line) — handy for tallying skip causes.

## Status

Wired up and passing real cases. An indicative TLS 1.2 client slice
(`-num-workers 2`) currently yields roughly **17 passed / 34 failed / 148
skipped** — e.g. `VersionNegotiation-Client-*`, `MinimumVersion-Client-*`,
`NoClientCertificate-TLS12`, and `ServerNameExtensionClient-*` pass.

Known triage items (the "handle later" bucket):

- **Resumption-bundled tests are skipped.** Many otherwise-passing handshake
  tests set `resumeSession`, so the shim reports them unimplemented. TLSNotary
  has no resumption support.
- **Some signature schemes are unsupported.** Client auth itself works (e.g.
  `Client-Sign-RSA_PKCS1_SHA256-TLS12` passes), but legacy schemes such as
  RSA-PKCS1-SHA1 fail, as do tests where the server signs with a scheme outside
  TLSNotary's set (RSA-PSS-*, RSA-PKCS1-SHA{256,384,512}).
- **Keying-material export** (`-export-keying-material`) is ignored, so tests
  asserting exporter output fail.
- **Post-handshake / extra-handshake messages** (e.g. `ExtraHandshake-Client`)
  are rejected by MPC-TLS as `unexpected record content type: Handshake`.
- **A robustness bug:** some scenarios where the runner aborts the connection
  early (e.g. `GREASE-Client-TLS12`) crash the shim with a stack overflow in the
  MPC stack — worth a separate TLSNotary issue.
- **Expected-error tests** won't match until `bogo/config.json`'s `ErrorMap`
  maps runner error tokens (e.g. `NO_SHARED_CIPHER`) to TLSNotary's messages.
