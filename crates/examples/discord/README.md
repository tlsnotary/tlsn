# Notarize Discord DMs

The `discord_dm.rs` example sets up a TLS connection with Discord and notarizes the requested DMs. The attestation and secrets are saved to disk.

This involves 3 steps:
1. Configure the inputs
2. Start the (local) notary server
3. Notarize

## Inputs

In this tlsn/examples/discord folder, create a `.env` file.
Then in that `.env` file, set the values of the following constants by following the format shown in this [example env file](./.env.example).

| Name          | Example                                                                          | Location                                      |
| ------------- | -------------------------------------------------------------------------------- | --------------------------------------------- |
| USER_AGENT    | `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0` | Look for `User-Agent` in a request headers    |
| AUTHORIZATION | `MTE1NDe1Otg4N6NxNjczOTM2OA.GYbUBf.aDtcMUKDOmg6C2kxxFtlFSN1pgdMMBtpHgBBEs`       | Look for `Authorization` in a request headers |
| CHANNEL_ID    | `1154750485639745567`                                                            | URL                                           |

You can obtain these parameters by opening [Discord](https://discord.com/channels/@me) in your browser and accessing the message history you want to notarize. Please note that notarizing only works for short transcripts at the moment, so choose a contact with a short history.

Next, open the **Developer Tools**, go to the **Network** tab, and refresh the page. Then, click on **Search** and type `/api` to filter results to Discord API requests. From there you can copy the needed information into your `.env` as indicated above.

You can find the `CHANNEL_ID` directly in the url:

`https://discord.com/channels/@me/{CHANNEL_ID)`

## Start the notary server
1. Edit the notary server [config file](../../notary/server/config/config.yaml) to turn off TLS so that self-signed certificates can be avoided (⚠️ this is only for local development purposes — TLS must be used in production).
   ```yaml
    tls:
        enabled: false
        ...
   ```
2. Run the following at the root level of this repository to start the notary server:
   ```shell
   cd crates/notary/server
   cargo run --release
   ```

The notary server will now be running in the background waiting for connections.

For more information on how to configure the `Notary` server, please refer to [this](../../notary/server/README.md#running-the-server).

## Notarize

In this tlsn/examples/discord folder, run the following command:

```sh
RUST_LOG=DEBUG,uid_mux=INFO,yamux=INFO cargo run --release --example discord_dm
```

If everything goes well, you should see output similar to the following:

```log
...
2024-06-26T08:49:47.017439Z DEBUG connect:tls_connection: tls_client_async: handshake complete
2024-06-26T08:49:48.676459Z DEBUG connect:tls_connection: tls_client_async: server closed connection
2024-06-26T08:49:48.676481Z DEBUG connect:commit: tls_mpc::leader: committing to transcript
2024-06-26T08:49:48.676503Z DEBUG connect:tls_connection: tls_client_async: client shutdown
2024-06-26T08:49:48.676466Z DEBUG discord_dm: Sent request
2024-06-26T08:49:48.676550Z DEBUG discord_dm: Request OK
2024-06-26T08:49:48.676598Z DEBUG connect:close_connection: tls_mpc::leader: closing connection
2024-06-26T08:49:48.676613Z DEBUG connect: tls_mpc::leader: leader actor stopped
2024-06-26T08:49:48.676618Z DEBUG discord_dm: [
  {
    "attachments": [],
    ...
    "channel_id": "1154750485639745567",
    ...
  }
]
2024-06-26T08:49:48.678621Z DEBUG finalize: tlsn_prover::tls::notarize: starting finalization
2024-06-26T08:49:48.680839Z DEBUG finalize: tlsn_prover::tls::notarize: received OT secret
2024-06-26T08:49:50.004432Z  INFO finalize:poll{role=Client}:handle_shutdown: uid_mux::yamux: mux connection closed
2024-06-26T08:49:50.004448Z  INFO finalize:poll{role=Client}: uid_mux::yamux: connection complete
2024-06-26T08:49:50.004583Z DEBUG discord_dm: Notarization complete!
```

If the transcript was too long, you may encounter the following error. This occurs because there is a default limit of notarization size to 16kB:

```
thread 'tokio-runtime-worker' panicked at 'called `Result::unwrap()` on an `Err` value: IOError(Custom { kind: InvalidData, error: BackendError(DecryptionError("Other: KOSReceiverActor is not setup")) })', /Users/heeckhau/tlsnotary/tlsn/tlsn/tlsn-prover/src/lib.rs:173:50
```

# Verify

See the [`present`](../attestation/present.rs) and [`verify`](../attestation/verify.rs) examples for a demonstration of how to construct a presentation and verify it.