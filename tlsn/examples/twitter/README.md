# Notarize Twitter DMs

The `twtter_dm.rs` example sets up a TLS connection with Twitter and notarizes the requested DMs. The full received transcript is notarized in one commitment, so nothing is redacted. The resulting proof is written to a local JSON file (`twitter_dm_proof.json`) for easier inspection.

This involves 3 steps:
1. Configure the inputs
2. Start the (local) notary server
3. Notarize

## Inputs

In this tlsn/examples/twitter folder, create a `.env` file.
Then in that `.env` file, set the values of the following constants by following the format shown in this [example env file](./.env.example).

| Name            | Example                                                 | Location in Request Headers Section (within Network Tab of Developer Tools)      |
| --------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------- |
| CONVERSATION_ID | `20124652-973145016511139841`                           | Look for `Referer`, then extract the `ID` in `https://twitter.com/messages/<ID>` |
| AUTH_TOKEN      | `670ccccccbe2bbbbbbbc1025aaaaaafa55555551`              | Look for `Cookie`, then extract the `token` in `;auth_token=<token>;`            |
| ACCESS_TOKEN    | `AAAAAAAAAAAAAAAAAAAAANRILgAA...4puTs%3D1Zv7...WjCpTnA` | Look for `Authorization`, then extract the `token` in `Bearer <token>`           |
| CSRF_TOKEN      | `77d8ef46bd57f722ea7e9f...f4235a713040bfcaac1cd6909`    | Look for `X-Csrf-Token`, then copy the entire value                              |

You can obtain these parameters by opening [Twitter](https://twitter.com/messages/) in your browser and accessing the message history you want to notarize. Please note that notarizing only works for short transcripts at the moment, so choose a contact with a short history.

Next, open the **Developer Tools**, go to the **Network** tab, and refresh the page. Then, click on **Search** and type `uuid` as shown in the screenshot below — all of these constants should be under the **Request Headers** section. Refer to the table above on where to find each of the constant value.

![Screenshot](twitter_dm_browser.png)

## Start the notary server
1. Edit the notary server [config file](../../../notary/server/config/config.yaml) to turn off TLS so that self-signed certificates can be avoided.
   ```yaml
    tls:
        enabled: false
        ...
   ```
2. Run the following at the root level of this repository to start the notary server:
   ```shell
   cd notary/server
   cargo run --release
   ```

The notary server will now be running in the background waiting for connections.

For more information on how to configure the notary server, please refer to [this](../../../notary/server/README.md#running-the-server).

## Notarize

In this tlsn/examples/twitter folder, run the following command:

```sh
RUST_LOG=debug,yamux=info cargo run --release --example twitter_dm
```

If everything goes well, you should see output similar to the following:

```log
 Compiling tlsn-examples v0.0.0 (/Users/heeckhau/tlsnotary/tlsn/tlsn/examples)
    Finished `release` profile [optimized] target(s) in 13.47s
     Running `/Users/heeckhau/tlsnotary/tlsn/tlsn/target/release/examples/twitter_dm`
2024-06-26T08:04:50.852870Z DEBUG notary_client::client: Setting up tcp connection...
2024-06-26T08:04:50.853621Z DEBUG notary_client::client: Sending configuration request: Request { method: POST, uri: http://127.0.0.1:7047/session, version: HTTP/1.1, headers: {"host": "127.0.0.1", "content-type": "application/json"}, body: Left(Full { data: Some(b"{\"clientType\":\"Tcp\",\"maxSentData\":4096,\"maxRecvData\":16384}") }) }
2024-06-26T08:04:50.854426Z DEBUG notary_client::client: Sent configuration request
2024-06-26T08:04:50.854500Z DEBUG notary_client::client: Configuration response: NotarizationSessionResponse { session_id: "d7c7b4a9-5883-4451-aa55-22ca4a830004" }
2024-06-26T08:04:50.854520Z DEBUG notary_client::client: Sending notarization request: Request { method: GET, uri: http://127.0.0.1:7047/notarize?sessionId=d7c7b4a9-5883-4451-aa55-22ca4a830004, version: HTTP/1.1, headers: {"host": "127.0.0.1", "connection": "Upgrade", "upgrade": "TCP"}, body: Right(Empty) }
2024-06-26T08:04:50.854819Z DEBUG notary_client::client: Sent notarization request
2024-06-26T08:04:50.855440Z DEBUG setup:setup_mpc_backend:open{role=Client id="00"}: uid_mux::yamux: opening stream: 2d3adedf
2024-06-26T08:04:50.855449Z DEBUG setup:setup_mpc_backend:open{role=Client id="01"}: uid_mux::yamux: opening stream: 48fc721f
...
2024-06-26T08:04:50.855597Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: allocated new stream
2024-06-26T08:04:50.855602Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: allocated new stream
...
2024-06-26T08:04:50.855926Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: allocated new stream
2024-06-26T08:04:50.855929Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: b76ffa77
...
2024-06-26T08:04:50.855988Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: ab13bedf
2024-06-26T08:04:50.856090Z DEBUG setup:setup_mpc_backend:open{role=Client id="00"}: uid_mux::yamux: caller received stream
...
2024-06-26T08:04:50.856181Z DEBUG setup:setup_mpc_backend:open{role=Client id="0c"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:50.856491Z DEBUG setup:setup_mpc_backend:open{role=Client id="6d70635f746c73"}: uid_mux::yamux: opening stream: 7efef773
2024-06-26T08:04:50.856512Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 7efef773
2024-06-26T08:04:50.856539Z DEBUG setup:setup_mpc_backend:open{role=Client id="6d70635f746c73"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:50.857716Z DEBUG setup:setup_mpc_backend:setup:preprocess:open{role=Client id="0100"}: uid_mux::yamux: opening stream: 687376c9
2024-06-26T08:04:50.857737Z DEBUG setup:setup_mpc_backend:setup:preprocess:open{role=Client id="0101"}: uid_mux::yamux: opening stream: 2022ec9d
2024-06-26T08:04:50.858038Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=2}:open{role=Client id="0200"}: uid_mux::yamux: opening stream: cd60d752
2024-06-26T08:04:50.858045Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=2}:open{role=Client id="0201"}: uid_mux::yamux: opening stream: 6abc4fcd
2024-06-26T08:04:50.860015Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 687376c9
...
2024-06-26T08:04:50.860032Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: cd60d752
2024-06-26T08:04:50.861702Z DEBUG setup:setup_mpc_backend:setup:preprocess:open{role=Client id="0100"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:50.861774Z DEBUG setup:setup_mpc_backend:setup:preprocess:open{role=Client id="0101"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:50.861859Z DEBUG setup:setup_mpc_backend:setup:preprocess:open{role=Client id="010100"}: uid_mux::yamux: opening stream: 44c659d1
2024-06-26T08:04:50.861869Z DEBUG setup:setup_mpc_backend:setup:preprocess:open{role=Client id="010101"}: uid_mux::yamux: opening stream: 8b3fa04e
2024-06-26T08:04:50.861875Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=2}:open{role=Client id="0201"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:50.861881Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=2}:open{role=Client id="0200"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:50.862450Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 44c659d1
2024-06-26T08:04:50.862466Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 8b3fa04e
2024-06-26T08:04:50.862527Z DEBUG setup:setup_mpc_backend:setup:preprocess:open{role=Client id="010100"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:50.862537Z DEBUG setup:setup_mpc_backend:setup:preprocess:open{role=Client id="010101"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:51.719625Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=3}:open{role=Client id="0300"}: uid_mux::yamux: opening stream: fd07e5b6
2024-06-26T08:04:51.719651Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=3}:open{role=Client id="0301"}: uid_mux::yamux: opening stream: 07ebe7a4
2024-06-26T08:04:51.719659Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 07ebe7a4
2024-06-26T08:04:51.719714Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: fd07e5b6
2024-06-26T08:04:51.719761Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=3}:open{role=Client id="0301"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:51.719770Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=3}:open{role=Client id="0300"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.134639Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=4}:open{role=Client id="0400"}: uid_mux::yamux: opening stream: 26774de0
2024-06-26T08:04:52.134661Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=4}:open{role=Client id="0401"}: uid_mux::yamux: opening stream: d65fe7e0
2024-06-26T08:04:52.134669Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 26774de0
2024-06-26T08:04:52.134711Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: d65fe7e0
2024-06-26T08:04:52.134742Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=4}:open{role=Client id="0400"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.134752Z DEBUG setup:setup_mpc_backend:setup:preprocess:load{role=Leader thread=4}:open{role=Client id="0401"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.212457Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=4096}:preprocess:load{role=Leader thread=5}:open{role=Client id="0500"}: uid_mux::yamux: opening stream: 453043f3
2024-06-26T08:04:52.212481Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=4096}:preprocess:load{role=Leader thread=5}:open{role=Client id="0501"}: uid_mux::yamux: opening stream: 4cdcd108
2024-06-26T08:04:52.223423Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=4096}:preprocess:preprocess:load{role=Leader thread=6}:open{role=Client id="0600"}: uid_mux::yamux: opening stream: a14b2737
2024-06-26T08:04:52.223438Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=4096}:preprocess:preprocess:load{role=Leader thread=6}:open{role=Client id="0601"}: uid_mux::yamux: opening stream: ad44e3c8
2024-06-26T08:04:52.223500Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=256}:preprocess:load{role=Leader thread=9}:open{role=Client id="0900"}: uid_mux::yamux: opening stream: 27156248
2024-06-26T08:04:52.223553Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=256}:preprocess:load{role=Leader thread=9}:open{role=Client id="0901"}: uid_mux::yamux: opening stream: cb9a73d3
2024-06-26T08:04:52.224223Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=256}:preprocess:preprocess:load{role=Leader thread=10}:open{role=Client id="0a00"}: uid_mux::yamux: opening stream: 1f689a45
2024-06-26T08:04:52.224238Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=256}:preprocess:preprocess:load{role=Leader thread=10}:open{role=Client id="0a01"}: uid_mux::yamux: opening stream: 3240bbb2
2024-06-26T08:04:52.224355Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: ad44e3c8
...
2024-06-26T08:04:52.224414Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: a14b2737
2024-06-26T08:04:52.224462Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=4096}:preprocess:load{role=Leader thread=5}:open{role=Client id="0501"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.224472Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=4096}:preprocess:load{role=Leader thread=5}:open{role=Client id="0500"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.224508Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=4096}:preprocess:preprocess:load{role=Leader thread=6}:open{role=Client id="0601"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.224520Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=4096}:preprocess:preprocess:load{role=Leader thread=6}:open{role=Client id="0600"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.224551Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=256}:preprocess:load{role=Leader thread=9}:open{role=Client id="0901"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.224560Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=256}:preprocess:load{role=Leader thread=9}:open{role=Client id="0900"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.224582Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=256}:preprocess:preprocess:load{role=Leader thread=10}:open{role=Client id="0a00"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:52.225007Z DEBUG setup:setup_mpc_backend:setup:preprocess{len=256}:preprocess:preprocess:load{role=Leader thread=10}:open{role=Client id="0a01"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.858949Z DEBUG setup:setup_mpc_backend:setup:set_client_random:open{role=Client id="030000"}: uid_mux::yamux: opening stream: 48332ab0
2024-06-26T08:04:53.858970Z DEBUG setup:setup_mpc_backend:setup:set_client_random:open{role=Client id="030001"}: uid_mux::yamux: opening stream: ec91e528
2024-06-26T08:04:53.858999Z DEBUG setup:setup_mpc_backend:setup:set_client_random:open{role=Client id="030100"}: uid_mux::yamux: opening stream: 78c8897e
2024-06-26T08:04:53.859004Z DEBUG setup:setup_mpc_backend:setup:set_client_random:open{role=Client id="030101"}: uid_mux::yamux: opening stream: cece43b1
2024-06-26T08:04:53.859010Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 48332ab0
2024-06-26T08:04:53.859013Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: cece43b1
2024-06-26T08:04:53.859016Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 78c8897e
2024-06-26T08:04:53.859075Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: ec91e528
2024-06-26T08:04:53.859102Z DEBUG setup:setup_mpc_backend:setup:set_client_random:open{role=Client id="030000"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.859110Z DEBUG setup:setup_mpc_backend:setup:set_client_random:open{role=Client id="030001"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.859159Z DEBUG setup:setup_mpc_backend:setup:set_client_random:open{role=Client id="030101"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.859165Z DEBUG setup:setup_mpc_backend:setup:set_client_random:open{role=Client id="030100"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.860371Z DEBUG setup:setup_mpc_backend: tlsn_prover::tls: MPC backend setup complete
2024-06-26T08:04:53.860419Z DEBUG setup:open{role=Client id="746c736e6f74617279"}: uid_mux::yamux: opening stream: cb48beb0
2024-06-26T08:04:53.860428Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: cb48beb0
2024-06-26T08:04:53.860445Z DEBUG setup:open{role=Client id="746c736e6f74617279"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.860455Z DEBUG setup:open{role=Client id="0d"}: uid_mux::yamux: opening stream: 8e3221f5
2024-06-26T08:04:53.860461Z DEBUG setup:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 8e3221f5
2024-06-26T08:04:53.860470Z DEBUG setup:open{role=Client id="0d"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.873865Z DEBUG twitter_dm: Sending request
2024-06-26T08:04:53.885021Z DEBUG connect:tls_connection: tls_client::client::hs: ALPN protocol is None    
2024-06-26T08:04:53.885035Z DEBUG connect:tls_connection: tls_client::client::hs: Using ciphersuite Tls12(Tls12CipherSuite { suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, algorithm: AES_128_GCM })    
2024-06-26T08:04:53.885182Z DEBUG connect:tls_connection: tls_client::client::tls12: ECDHE curve is ECParameters { curve_type: NamedCurve, named_group: secp256r1 }    
2024-06-26T08:04:53.885196Z DEBUG connect:tls_connection: tls_client::client::tls12: Server DNS name is DnsName(DnsName(DnsName("x.com")))    
2024-06-26T08:04:53.885496Z DEBUG connect:handle:client_key: key_exchange::exchange: received public key share from follower
2024-06-26T08:04:53.886552Z DEBUG connect:handle:compute_pms:execute{role=Leader thread=2}:open{role=Client id="020000"}: uid_mux::yamux: opening stream: fff22b1e
2024-06-26T08:04:53.886568Z DEBUG connect:handle:compute_pms:execute{role=Leader thread=2}:open{role=Client id="020001"}: uid_mux::yamux: opening stream: 62531926
2024-06-26T08:04:53.886596Z DEBUG connect:handle:compute_pms:execute{role=Leader thread=2}:open{role=Client id="020100"}: uid_mux::yamux: opening stream: 848253e6
2024-06-26T08:04:53.886602Z DEBUG connect:handle:compute_pms:execute{role=Leader thread=2}:open{role=Client id="020101"}: uid_mux::yamux: opening stream: 301ec32e
2024-06-26T08:04:53.886615Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: fff22b1e
2024-06-26T08:04:53.886619Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 848253e6
2024-06-26T08:04:53.886622Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 62531926
2024-06-26T08:04:53.886651Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 301ec32e
2024-06-26T08:04:53.886682Z DEBUG connect:handle:compute_pms:execute{role=Leader thread=2}:open{role=Client id="020000"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.886705Z DEBUG connect:handle:compute_pms:execute{role=Leader thread=2}:open{role=Client id="020001"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.886816Z DEBUG connect:handle:compute_pms:execute{role=Leader thread=2}:open{role=Client id="020100"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:53.886823Z DEBUG connect:handle:compute_pms:execute{role=Leader thread=2}:open{role=Client id="020101"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.593366Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=5}:open{role=Client id="050000"}: uid_mux::yamux: opening stream: 1aa645a4
2024-06-26T08:04:54.593389Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=5}:open{role=Client id="050001"}: uid_mux::yamux: opening stream: 6dc18726
2024-06-26T08:04:54.593400Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=5}:open{role=Client id="050100"}: uid_mux::yamux: opening stream: d723063c
2024-06-26T08:04:54.593456Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=5}:open{role=Client id="050101"}: uid_mux::yamux: opening stream: 65fafd9d
2024-06-26T08:04:54.593478Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=9}:open{role=Client id="090000"}: uid_mux::yamux: opening stream: df372163
2024-06-26T08:04:54.593484Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=9}:open{role=Client id="090001"}: uid_mux::yamux: opening stream: 94effdfd
2024-06-26T08:04:54.593524Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=9}:open{role=Client id="090100"}: uid_mux::yamux: opening stream: 29484491
2024-06-26T08:04:54.593529Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=9}:open{role=Client id="090101"}: uid_mux::yamux: opening stream: 0e971e4c
2024-06-26T08:04:54.593571Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 0e971e4c
2024-06-26T08:04:54.593575Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 94effdfd
2024-06-26T08:04:54.593578Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 6dc18726
2024-06-26T08:04:54.593581Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: df372163
2024-06-26T08:04:54.593599Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: d723063c
2024-06-26T08:04:54.593602Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 65fafd9d
2024-06-26T08:04:54.593605Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 29484491
2024-06-26T08:04:54.593608Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 1aa645a4
2024-06-26T08:04:54.593671Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=5}:open{role=Client id="050001"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.593678Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=5}:open{role=Client id="050000"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.593720Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=5}:open{role=Client id="050100"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.593725Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=5}:open{role=Client id="050101"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.593735Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=9}:open{role=Client id="090001"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.593740Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=9}:open{role=Client id="090000"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.593766Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=9}:open{role=Client id="090101"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.593772Z DEBUG connect:handle:start:encrypt_share:execute{role=Leader thread=9}:open{role=Client id="090100"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.740650Z DEBUG connect:encrypt_client_finished:encrypt_public:encrypt_public:compute:open{role=Client id="060000"}: uid_mux::yamux: opening stream: a5ab409f
2024-06-26T08:04:54.740672Z DEBUG connect:encrypt_client_finished:encrypt_public:encrypt_public:compute:open{role=Client id="060001"}: uid_mux::yamux: opening stream: 3686c027
2024-06-26T08:04:54.740682Z DEBUG connect:encrypt_client_finished:encrypt_public:encrypt_public:compute:open{role=Client id="060100"}: uid_mux::yamux: opening stream: 21545cfc
2024-06-26T08:04:54.740745Z DEBUG connect:encrypt_client_finished:encrypt_public:encrypt_public:compute:open{role=Client id="060101"}: uid_mux::yamux: opening stream: a40c3c82
2024-06-26T08:04:54.740762Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: a5ab409f
2024-06-26T08:04:54.740766Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: a40c3c82
2024-06-26T08:04:54.740769Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 3686c027
2024-06-26T08:04:54.740822Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 21545cfc
2024-06-26T08:04:54.740854Z DEBUG connect:encrypt_client_finished:encrypt_public:encrypt_public:compute:open{role=Client id="060000"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.740863Z DEBUG connect:encrypt_client_finished:encrypt_public:encrypt_public:compute:open{role=Client id="060001"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.740885Z DEBUG connect:encrypt_client_finished:encrypt_public:encrypt_public:compute:open{role=Client id="060101"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.740890Z DEBUG connect:encrypt_client_finished:encrypt_public:encrypt_public:compute:open{role=Client id="060100"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.818808Z DEBUG connect:decrypt_server_finished:decrypt_public:verify_tag:share_keystream_block:compute:open{role=Client id="0a0000"}: uid_mux::yamux: opening stream: c5c230e3
2024-06-26T08:04:54.818833Z DEBUG connect:decrypt_server_finished:decrypt_public:verify_tag:share_keystream_block:compute:open{role=Client id="0a0001"}: uid_mux::yamux: opening stream: e5390402
2024-06-26T08:04:54.818847Z DEBUG connect:decrypt_server_finished:decrypt_public:verify_tag:share_keystream_block:compute:open{role=Client id="0a0100"}: uid_mux::yamux: opening stream: d57e3903
2024-06-26T08:04:54.818887Z DEBUG connect:decrypt_server_finished:decrypt_public:verify_tag:share_keystream_block:compute:open{role=Client id="0a0101"}: uid_mux::yamux: opening stream: 633f72c2
2024-06-26T08:04:54.818927Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: 633f72c2
2024-06-26T08:04:54.818931Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: c5c230e3
2024-06-26T08:04:54.818964Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: e5390402
2024-06-26T08:04:54.818972Z DEBUG connect:prover:poll{role=Client}:client_handle_outbound: uid_mux::yamux: opened new stream: d57e3903
2024-06-26T08:04:54.819004Z DEBUG connect:decrypt_server_finished:decrypt_public:verify_tag:share_keystream_block:compute:open{role=Client id="0a0000"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.819014Z DEBUG connect:decrypt_server_finished:decrypt_public:verify_tag:share_keystream_block:compute:open{role=Client id="0a0001"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.819047Z DEBUG connect:decrypt_server_finished:decrypt_public:verify_tag:share_keystream_block:compute:open{role=Client id="0a0101"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.819060Z DEBUG connect:decrypt_server_finished:decrypt_public:verify_tag:share_keystream_block:compute:open{role=Client id="0a0100"}: uid_mux::yamux: caller received stream
2024-06-26T08:04:54.975725Z DEBUG connect:tls_connection: tls_client_async: handshake complete
2024-06-26T08:04:55.597934Z DEBUG connect:tls_connection: tls_client_async: server closed connection
2024-06-26T08:04:55.597959Z DEBUG connect:commit: tls_mpc::leader: committing to transcript
2024-06-26T08:04:58.860219Z DEBUG connect:tls_connection: tls_client_async: client shutdown
2024-06-26T08:04:58.860229Z DEBUG twitter_dm: Sent request
2024-06-26T08:04:58.860261Z DEBUG twitter_dm: Request OK
2024-06-26T08:04:58.860302Z DEBUG connect:close_connection: tls_mpc::leader: closing connection
2024-06-26T08:04:58.860309Z DEBUG connect: tls_mpc::leader: leader actor stopped
2024-06-26T08:04:58.860334Z DEBUG twitter_dm: {
  "conversation_timeline": {
    "entries": [
      {
        "message": {
          ...
        }
      },
      ...
  }
}
2024-06-26T08:04:58.868457Z DEBUG finalize: tlsn_prover::tls::notarize: starting finalization
2024-06-26T08:04:58.871895Z DEBUG finalize: tlsn_prover::tls::notarize: received OT secret
2024-06-26T08:05:01.352858Z  INFO finalize:poll{role=Client}:client_handle_inbound: uid_mux::yamux: remote closed connection
2024-06-26T08:05:01.352872Z  INFO finalize:poll{role=Client}: uid_mux::yamux: connection complete
2024-06-26T08:05:01.353016Z DEBUG twitter_dm: Notarization complete!
```

If the transcript was too long, you may encounter the following error:

```
thread 'tokio-runtime-worker' panicked at 'called `Result::unwrap()` on an `Err` value: IOError(Custom { kind: InvalidData, error: BackendError(DecryptionError("Other: KOSReceiverActor is not setup")) })', /Users/heeckhau/tlsnotary/tlsn/tlsn/tlsn-prover/src/lib.rs:173:50
```

> **_NOTE:_** ℹ️ <https://explorer.tlsnotary.org/> hosts a generic proof visualizer. Drag and drop your proof into the drop zone to check and render your proof.