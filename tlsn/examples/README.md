This folder contains examples showing how to use the TLSNotary protocol. 

`quick_start.md` shows how to perform a simple notarization.

`twitter_dm.md` shows how to notarize a Twitter DM.


### Starting a notary server

Before running the examples please make sure that the Notary server is already running. The server can be started with the following command at the root level of this repository:

```shell
cd notary-server
cargo run --release
```

By default the server will be listening on 127.0.0.1:7047
