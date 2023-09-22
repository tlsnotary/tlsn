# Notarize Discord DMs

The `discord_dm.rs` example sets up a TLS connection with Discord and notarizes the requested DMs. The notarized session is written to a local JSON file (`discord_dm_notarized_session.json`) for easier inspection.

This involves 3 steps:
1. Configure the inputs
2. Start the (local) notary server
3. Notarize

## Inputs

In this tlsn/examples folder, create a `.env` file.
Then in that `.env` file, set the values of the following constants by following the format shown in this [example env file](./.env.example).

| Name            | Example                                                 | Location      |
| --------------- | ------------------------------------------------------- |---------------------------------------------------------------------------------- |
| USER_AGENT | `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0` | Look for `User-Agent` in a request headers | 
| AUTHORIZATION    | `MTE1NDe1Otg4N6NxNjczOTM2OA.GYbUBf.aDtcMUKDOmg6C2kxxFtlFSN1pgdMMBtpHgBBEs` | Look for `Authorization` in a request headers |   
| CHANNEL_ID      | `1154750485639745567` | URL  |    

You can obtain these parameters by opening [Discord](https://discord.com/channels/@me) in your browser and accessing the message history you want to notarize. Please note that notarizing only works for short transcripts at the moment, so choose a contact with a short history.

Next, open the **Developer Tools**, go to the **Network** tab, and refresh the page. Then, click on **Search** and type `/api` to filter results to Discord API requests. From there you can copy the needed information into your `.env` as indicated above.

You can find the `CHANNEL_ID` directly in the url:

`https://discord.com/channels/@me/{CHANNEL_ID)`

## Start the notary server

Make sure you checkout a recent release and it matches the version of `tlsn`!

```
git clone https://github.com/tlsnotary/notary-server
cd notary-server
cargo run --release
```

The notary server will now be running in the background waiting for connections.

For more information on how to configure the notary server, please refer to [this](https://github.com/tlsnotary/notary-server#running-the-server).

## Notarize

In this tlsn/examples/discord folder, run the following command:

```sh
RUST_LOG=debug,yamux=info cargo run --release --example discord_dm
```

If everything goes well, you should see output similar to the following:

```log
..
2023-09-22T14:40:51.416047Z DEBUG discord_dm: [
  {
    "attachments": [],
    "author": {
      "accent_color": null,
      "avatar": "dd07631c9613240aa969d6e7916eb7ae",
      "avatar_decoration_data": null,
      "banner": null,
      "banner_color": null,
      "discriminator": "0",
      "flags": 0,
      "global_name": "sinu",
      "id": "662709891017867273",
      "public_flags": 0,
      "username": "sinu_"
    },
    "channel_id": "1154750485639745567",
    "components": [],
    "content": "Hello ETHGlobal NY!!",
    "edited_timestamp": null,
    "embeds": [],
    "flags": 0,
    "id": "1154750835784429678",
    "mention_everyone": false,
    "mention_roles": [],
    "mentions": [],
    "pinned": false,
    "timestamp": "2023-09-22T12:07:33.484000+00:00",
    "tts": false,
    "type": 0
  },
  ..
]
2023-09-22T14:40:51.847455Z DEBUG discord_dm: Notarization complete!
```

If the transcript was too long, you may encounter the following error. This occurs because there is a default limit of notarization size to 16kB:

```
thread 'tokio-runtime-worker' panicked at 'called `Result::unwrap()` on an `Err` value: IOError(Custom { kind: InvalidData, error: BackendError(DecryptionError("Other: KOSReceiverActor is not setup")) })', /Users/heeckhau/tlsnotary/tlsn/tlsn/tlsn-prover/src/lib.rs:173:50
```

# Verifier

The `discord_dm` example also generated a proof of the transcript with the `Authorization` header redacted from the request, saved in `discord_dm_proof.json`.

We can verify this proof using the `discord_dm_verifier` by running:

```
cargo run --release --example discord_dm_verifier
```

This will verify the proof and print out the redacted transcript!
