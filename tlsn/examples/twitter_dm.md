# Notarize Twitter DMs

The `twtter_dm.rs` example sets up a TLS connection with Twitter and notarizes the requested DMs. The full received transcript is notarized in one commitment, so nothing is redacted. The result is written to a local JSON file (`twitter_dm.json`) for easier inspection.

This involves 3 steps:
1. Configure the inputs
2. Start the (local) notary server
3. Notarize

## Inputs

In this tlsn/examples folder, create a `.env` file.
Then in that `.env` file, set the values of the following constants by following the format shown in this [example env file](./.env.example).

| Name            | Example                                                 | Location in Request Headers Section (within Network Tab of Developer Tools)       |
| --------------- | ------------------------------------------------------- |---------------------------------------------------------------------------------- |
| CONVERSATION_ID | `20124652-973145016511139841`                           | Look for `Referer`, then extract the `ID` in `https://twitter.com/messages/<ID>`  |   
| CLIENT_UUID     | `e6f00000-cccc-dddd-bbbb-eeeeeefaaa27`                  | Look for `X-Client-Uuid`, then copy the entire value                              |   
| AUTH_TOKEN      | `670ccccccbe2bbbbbbbc1025aaaaaafa55555551`              | Look for `Cookie`, then extract the `token` in `;auth_token=<token>;`             |   
| ACCESS_TOKEN    | `AAAAAAAAAAAAAAAAAAAAANRILgAA...4puTs%3D1Zv7...WjCpTnA` | Look for `Authorization`, then extract the `token` in `Bearer <token>`            |   
| CSRF_TOKEN      | `77d8ef46bd57f722ea7e9f...f4235a713040bfcaac1cd6909`    | Look for `X-Csrf-Token`, then copy the entire value                               |    

You can obtain these parameters by opening [Twitter](https://twitter.com/messages/) in your browser and accessing the message history you want to notarize. Please note that notarizing only works for short transcripts at the moment, so choose a contact with a short history.

Next, open the **Developer Tools**, go to the **Network** tab, and refresh the page. Then, click on **Search** and type `uuid` as shown in the screenshot below — all of these constants should be under the **Request Headers** section. Refer to the table above on where to find each of the constant value.

![Screenshot](twitter_dm_browser.png)

## Start the notary server

```
git clone https://github.com/tlsnotary/notary-server
cd notary-server
cargo run --release
```

The notary server will now be running in the background waiting for connections.

For more information on how to configure the notary server, please refer to [this](https://github.com/tlsnotary/notary-server#running-the-server).

## Notarize

In this tlsn/examples folder, run the following command:

```sh
RUST_LOG=debug,yamux=info cargo run --release --example twitter_dm
```

If everything goes well, you should see output similar to the following:

```log
   Compiling tlsn-examples v0.0.0 (/Users/heeckhau/tlsnotary/tlsn/tlsn/examples)
    Finished release [optimized] target(s) in 8.52s
     Running `/Users/heeckhau/tlsnotary/tlsn/tlsn/target/release/examples/twitter_dm`
2023-08-15T12:49:38.532924Z DEBUG rustls::client::hs: No cached session for DnsName("tlsnotaryserver.io")
2023-08-15T12:49:38.533384Z DEBUG rustls::client::hs: Not resuming any session
2023-08-15T12:49:38.543493Z DEBUG rustls::client::hs: Using ciphersuite TLS13_AES_256_GCM_SHA384
2023-08-15T12:49:38.543632Z DEBUG rustls::client::tls13: Not resuming
2023-08-15T12:49:38.543792Z DEBUG rustls::client::tls13: TLS1.3 encrypted extensions: [ServerNameAck]
2023-08-15T12:49:38.543803Z DEBUG rustls::client::hs: ALPN protocol is None
2023-08-15T12:49:38.544305Z DEBUG twitter_dm: Sending configuration request
2023-08-15T12:49:38.544556Z DEBUG hyper::proto::h1::io: flushed 163 bytes
2023-08-15T12:49:38.546069Z DEBUG hyper::proto::h1::io: parsed 3 headers
2023-08-15T12:49:38.546078Z DEBUG hyper::proto::h1::conn: incoming body is content-length (52 bytes)
2023-08-15T12:49:38.546168Z DEBUG hyper::proto::h1::conn: incoming body completed
2023-08-15T12:49:38.546187Z DEBUG twitter_dm: Sent configuration request
2023-08-15T12:49:38.546192Z DEBUG twitter_dm: Response OK
2023-08-15T12:49:38.546224Z DEBUG twitter_dm: Notarization response: NotarizationSessionResponse { session_id: "2675e0f9-d06c-499b-8e9e-2b893a6d7356" }
2023-08-15T12:49:38.546257Z DEBUG twitter_dm: Sending notarization request
2023-08-15T12:49:38.546291Z DEBUG hyper::proto::h1::io: flushed 152 bytes
2023-08-15T12:49:38.546743Z DEBUG hyper::proto::h1::io: parsed 3 headers
2023-08-15T12:49:38.546748Z DEBUG hyper::proto::h1::conn: incoming body is empty
2023-08-15T12:49:38.546766Z DEBUG twitter_dm: Sent notarization request
2023-08-15T12:49:38.546772Z DEBUG twitter_dm: Switched protocol OK
2023-08-15T12:49:40.088422Z DEBUG twitter_dm: Sending request
2023-08-15T12:49:40.088464Z DEBUG hyper::proto::h1::io: flushed 950 bytes
2023-08-15T12:49:40.143884Z DEBUG tls_client::client::hs: ALPN protocol is None
2023-08-15T12:49:40.143893Z DEBUG tls_client::client::hs: Using ciphersuite Tls12(Tls12CipherSuite { suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, algorithm: AES_128_GCM })
2023-08-15T12:49:40.144666Z DEBUG tls_client::client::tls12: ECDHE curve is ECParameters { curve_type: NamedCurve, named_group: secp256r1 }
2023-08-15T12:49:40.144687Z DEBUG tls_client::client::tls12: Server DNS name is DnsName(DnsName(DnsName("twitter.com")))
2023-08-15T12:51:01.336491Z DEBUG hyper::proto::h1::io: parsed 31 headers
2023-08-15T12:51:01.336507Z DEBUG hyper::proto::h1::conn: incoming body is content-length (4330 bytes)
2023-08-15T12:51:01.336516Z DEBUG hyper::proto::h1::conn: incoming body completed
2023-08-15T12:51:01.336528Z DEBUG twitter_dm: Sent request
2023-08-15T12:51:01.336537Z DEBUG twitter_dm: Request OK
2023-08-15T12:51:01.336585Z DEBUG twitter_dm: {
  "conversation_timeline": {
    "entries": [
      {
        "message": {
          "conversation_id": "20124652-45653288",
        ...
        "withheld_in_countries": []
      }
    }
  }
}
2023-08-15T12:51:08.854818Z DEBUG twitter_dm: Notarization complete!
```

If the transcript was too long, you may encounter the following error:

```
thread 'tokio-runtime-worker' panicked at 'called `Result::unwrap()` on an `Err` value: IOError(Custom { kind: InvalidData, error: BackendError(DecryptionError("Other: KOSReceiverActor is not setup")) })', /Users/heeckhau/tlsnotary/tlsn/tlsn/tlsn-prover/src/lib.rs:173:50
```
