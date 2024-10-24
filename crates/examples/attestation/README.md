## Simple Attestation Example: Notarize Public Data from example.com (Rust) <a name="rust-simple"></a>

This example demonstrates the simplest possible use case for TLSNotary:
1. Fetch <https://example.com/> and acquire an attestation of its content.
2. Create a verifiable presentation using the attestation, while redacting the value of a header.
3. Verify the presentation.

### 1. Notarize <https://example.com/>

Run the `prove` binary.

```shell
cargo run --release --example attestation_prove
```

If the notarization was successful, you should see this output in the console:

```log
Starting an MPC TLS connection with the server
Got a response from the server
Notarization completed successfully!
The attestation has been written to `example.attestation.tlsn` and the corresponding secrets to `example.secrets.tlsn`.
```

⚠️ In this simple example the `Notary` server is automatically started in the background. Note that this is for demonstration purposes only. In a real world example, the notary should be run by a trusted party. Consult the [Notary Server Docs](https://docs.tlsnotary.org/developers/notary_server.html) for more details on how to run a notary server.

### 2. Build a verifiable presentation

This will build a verifiable presentation with the `User-Agent` header redacted from the request. This presentation can be shared with any verifier you wish to present the data to.

Run the `present` binary.

```shell
cargo run --release --example attestation_present
```

If successful, you should see this output in the console:

```log
Presentation built successfully!
The presentation has been written to `example.presentation.tlsn`.
```

### 3. Verify the presentation

This will read the presentation from the previous step, verify it, and print the disclosed data to console.

Run the `verify` binary.

```shell
cargo run --release --example attestation_verify
```

If successful, you should see this output in the console:

```log
Verifying presentation with {key algorithm} key: { hex encoded key }

**Ask yourself, do you trust this key?**

-------------------------------------------------------------------
Successfully verified that the data below came from a session with example.com at 2024-10-03 03:01:40 UTC.
Note that the data which the Prover chose not to disclose are shown as X.

Data sent:
...
```

⚠️ Notice that the presentation comes with a "verifying key". This is the key the Notary used when issuing the attestation that the presentation was built from. If you trust the Notary, or more specifically the verifying key, then you can trust that the presented data is authentic.

### Next steps

Try out the [Discord example](../discord/README.md) and notarize a Discord conversations.


