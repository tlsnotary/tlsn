## Simple Example: Notarize Public Data from example.com (Rust) <a name="rust-simple"></a>

This example demonstrates the simplest possible use case for TLSNotary:
1. Notarize: Fetch <https://example.com/> and create a proof of its content.
2. Verify the proof.

Next, we will redact the content and verify it again:
1. Redact the `USER_AGENT` and titles.
2. Verify the redacted proof.

### 1. Notarize <https://example.com/>

Run a simple prover:

```shell
cargo run --release --example simple_prover
```

If the notarization was successful, you should see this output in the console:

```log
Starting an MPC TLS connection with the server
Got a response from the server
Notarization completed successfully!
The proof has been written to `simple_proof.json`
```

⚠️ In this simple example the `Notary` server is automatically started in the background. Note that this is for demonstration purposes only. In a real work example, the notary should be run by a neutral party or the verifier of the proofs. Consult the [Notary Server Docs](https://docs.tlsnotary.org/developers/notary_server.html) for more details on how to run a notary server.

### 2. Verify the Proof

When you open `simple_proof.json` in an editor, you will see a JSON file with lots of non-human-readable byte arrays. You can decode this file by running:

```shell
cargo run --release --example simple_verifier
```

This will output the TLS-transaction in clear text:

```log
Successfully verified that the bytes below came from a session with Dns("example.com") at 2023-11-03 08:48:20 UTC.
Note that the bytes which the Prover chose not to disclose are shown as X.

Bytes sent:
...
```

### 3. Redact Information

Open `simple/src/examples/simple_prover.rs` and locate the line with:

```rust
let redact = false;
```

and change it to:

```rust
let redact = true;
```

Next, if you run the `simple_prover` and `simple_verifier` again, you'll notice redacted `X`'s in the output:

```shell
cargo run --release --example simple_prover
cargo run --release --example simple_verifier
```

```log
<!doctype html>
<html>
<head>
    <title>XXXXXXXXXXXXXX</title>
...
```

You can also use <https://explorer.tlsnotary.org/> to inspect your proofs. Simply drag and drop `simple_proof.json` from your file explorer into the drop zone. Redacted bytes are marked with X characters. [Notary public key](../../../notary/server/fixture/notary/notary.pub)

### (Optional) Extra Experiments

Feel free to try these extra challenges:

- [ ] Modify the `server_name` (or any other data) in `simple_proof.json` and verify that the proof is no longer valid.
- [ ] Modify the `build_proof_with_redactions` function in `simple_prover.rs` to redact more or different data.

### Next steps

Try out the [Discord example](../Discord/README.md) and notarize a Discord conversations.


