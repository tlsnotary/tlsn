## Simple Attestation Example: Notarize Public Data from example.com (Rust) <a name="rust-simple"></a>

This example demonstrates the simplest possible use case for TLSNotary. A Prover notarizes data from a local test server with a local Notary.

**Overview**:
1. Notarize a request and response from the test server and acquire an attestation of its content.
2. Create a redacted, verifiable presentation using the attestation.
3. Verify the presentation.

### 1. Notarize

Before starting the notarization, set up the local test server and local notary.

1. Run the test server:
    ```shell
    PORT=4000 cargo run --bin tlsn-server-fixture
    ```
2. Run the notary server:
    ```shell
    cd crates/notary/server
    cargo run -r -- --tls-enabled false
    ```
3. Run the prove example:
    ```shell
    SERVER_PORT=4000 cargo run --release --example attestation_prove
    ```

To see more details, run with additional debug information:
```shell
RUST_LOG=debug,yamux=info,uid_mux=info SERVER_PORT=4000 cargo run --release --example attestation_prove
```

If notarization is successful, you should see the following output in the console:
```log
Starting an MPC TLS connection with the server
Got a response from the server
Notarization completed successfully!
The attestation has been written to `example-json.attestation.tlsn` and the corresponding secrets to `example-json.secrets.tlsn`.
```

⚠️ Note: In this example, we run a local Notary server for demonstration purposes. In real-world applications, the Notary should be operated by a trusted third party. Refer to the [Notary Server Documentation](https://docs.tlsnotary.org/developers/notary_server.html) for more details on running a Notary server.

### 2. Build a Verifiable Presentation

This step creates a verifiable presentation with optional redactions, which can be shared with any verifier.

Run the present example:
```shell
cargo run --release --example attestation_present
```

If successful, you’ll see this output in the console:

```log
Presentation built successfully!
The presentation has been written to `example-json.presentation.tlsn`.
```

You can create multiple presentations from the attestation and secrets in the notarization step, each with customized data redactions. You are invited to experiment!

### 3. Verify the Presentation

This step reads the presentation created above, verifies it, and prints the disclosed data to the console.

Run the verify binary:
```shell
cargo run --release --example attestation_verify
```

Upon success, you should see output similar to:
```log
Verifying presentation with {key algorithm} key: { hex encoded key }

**Ask yourself, do you trust this key?**

-------------------------------------------------------------------
Successfully verified that the data below came from a session with test-server.io at 2024-10-03 03:01:40 UTC.
Note that the data which the Prover chose not to disclose are shown as X.

Data sent:
...
```

⚠️ The presentation includes a “verifying key,” which the Notary used when issuing the attestation. If you trust this key, you can trust the authenticity of the presented data.

### HTML

In the example above, we notarized a JSON response. TLSNotary also supports notarizing HTML content. To run an HTML example, use:

```shell
# notarize
SERVER_PORT=4000 cargo run --release --example attestation_prove -- html
# present
cargo run --release --example attestation_present -- html
# verify
cargo run --release --example attestation_verify -- html
```

### Private Data

The examples above demonstrate how to use TLSNotary with publicly accessible data. TLSNotary can also be utilized for private data that requires authentication. To access this data, you can add the necessary headers (such as an authentication token) or cookies to your request. To run an example that uses an authentication token, execute the following command:

```shell
# notarize
SERVER_PORT=4000 cargo run --release --example attestation_prove -- authenticated
# present
cargo run --release --example attestation_present -- authenticated
# verify
cargo run --release --example attestation_verify -- authenticated
```