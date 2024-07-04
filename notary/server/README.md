# notary-server

An implementation of the notary server in Rust.

## ⚠️ Notice

This crate is currently under active development and should not be used in production. Expect bugs and regular major breaking changes.

---
## Running the server
### ⚠️ Notice
- When running this server against a prover (e.g. [Rust](https://github.com/tlsnotary/tlsn/tree/main/tlsn/examples) or [browser extension](https://github.com/tlsnotary/tlsn-extension)), please ensure that the prover's version is the same as the version of this server
- When running this server in a *production environment*, please first read this [page](https://docs.tlsnotary.org/developers/notary_server.html)
- When running this server in a *local environment* with a browser extension, please turn off this server's TLS in the config (refer [here](#optional-tls))

### Using Cargo
1. Configure the server setting in this config [file](./config/config.yaml) — refer [here](./src/config.rs) for more information on the definition of the setting parameters.
2. Start the server by running the following in a terminal at the root of this crate.
```bash
cargo run --release
```
3. To use a config file from a different location, run the following command to override the default config file location.
```bash
cargo run --release -- --config-file <path-of-new-config-file>
```

### Using Docker
There are two ways to obtain the notary server's Docker image:
- [GitHub](#obtaining-the-image-via-github)
- [Building from source](#building-from-source)

#### GitHub
1. Obtain the latest image with:
```bash
docker pull ghcr.io/tlsnotary/tlsn/notary-server:latest
```
2. Run the docker container with:
```bash
docker run --init -p 127.0.0.1:7047:7047 ghcr.io/tlsnotary/tlsn/notary-server:latest
```
3. If you want to change the default configuration, create a `config` folder locally, that contains a `config.yaml`, whose content follows the format of the default config file [here](./config/config.yaml).
4. Instead of step 2, run the docker container with the following (remember to change the port mapping if you have changed that in the config):
```bash
docker run --init -p 127.0.0.1:7047:7047 -v <your config folder path>:/root/.notary-server/config ghcr.io/tlsnotary/tlsn/notary-server:latest
```

#### Building from source
1. Configure the server setting in this config [file](./config/config.yaml).
2. Build the docker image by running the following in a terminal at the root of this *repository*.
```bash
docker build . -t notary-server:local -f notary/server/notary-server.Dockerfile
```
3. Run the docker container and specify the port specified in the config file, e.g. for the default port 7047
```bash
docker run --init -p 127.0.0.1:7047:7047 notary-server:local
```

### Using different setting files with Docker
1. Instead of changing the key/cert/auth file path(s) in the config file, create a folder containing your key/cert/auth files by following the folder structure [here](./fixture/).
2. When launching the docker container, mount your folder onto the docker container at the relevant path prefixed by `/root/.notary-server`.
- Example 1: Using different key, cert, and auth files:
```bash
docker run --init -p 127.0.0.1:7047:7047 -v <your folder path>:/root/.notary-server/fixture notary-server:local
```
- Example 2: Using a different key for notarizations:
```bash
docker run --init -p 127.0.0.1:7047:7047 -v <your folder path>:/root/.notary-server/fixture/notary notary-server:local
```
---
## API
All APIs are TLS-protected, hence please use `https://` or `wss://`.
### HTTP APIs
Defined in the [OpenAPI specification](./openapi.yaml).

### WebSocket APIs
#### /notarize
##### Description
To perform a notarization using a session id (an unique id returned upon calling the `/session` endpoint successfully).

##### Query Parameter
`sessionId`

##### Query Parameter Type
String

---
## Logging
The default logging strategy of this server is set to `DEBUG` verbosity level for the crates that are useful for most debugging scenarios, i.e. using the following filtering logic:

`notary_server=DEBUG,tlsn_verifier=DEBUG,tls_mpc=DEBUG,tls_client_async=DEBUG`

In the config [file](./config/config.yaml), one can toggle the verbosity level for these crates using the `level` field under `logging`.

One can also provide a custom filtering logic by adding a `filter` field  under `logging` in the config file above, and use a value that follows the tracing crate's [filter directive syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax).

---
## Architecture
### Objective
The main objective of a notary server is to perform notarizations together with a prover. In this case, the prover can either be a
1. TCP client — which has access and control over the transport layer, i.e. TCP
2. WebSocket client — which has no access over TCP and instead uses WebSocket for notarizations

### Features
#### Notarization Configuration
To perform a notarization, some parameters need to be configured by the prover and the notary server (more details in the [OpenAPI specification](./openapi.yaml)), i.e.
- maximum transcript size
- unique session id

To streamline this process, a single HTTP endpoint (`/session`) is used by both TCP and WebSocket clients.

#### Notarization
After calling the configuration endpoint above, the prover can proceed to start the notarization. For a TCP client, that means calling the `/notarize` endpoint using HTTP (`https`), while a WebSocket client should call the same endpoint but using WebSocket (`wss`). Example implementations of these clients can be found in the [integration test](../tests-integration/tests/notary.rs).

#### Signatures
Currently, both the private key (and cert) used to establish a TLS connection with the prover, and the private key used by the notary server to sign the notarized transcript, are hardcoded PEM keys stored in this repository. Though the paths of these keys can be changed in the config (`notary-key` field) to use different keys instead.

#### Authorization
An optional authorization module is available to only allow requests with a valid API key attached in the authorization header. The API key whitelist path (as well as the flag to enable/disable this module) can be changed in the config (`authorization` field).

Hot reloading of the whitelist is supported, i.e. modification of the whitelist file will be automatically applied without needing to restart the server. Please take note of the following
- Avoid using auto save mode when editing the whitelist to prevent spamming hot reloads
- Once the edit is saved, ensure that it has been reloaded successfully by checking the server log

#### Optional TLS
TLS between the prover and the notary is currently manually handled in this server, though it can be turned off if any of the following is true
- This server is run locally
- TLS is to be handled by an external environment, e.g. reverse proxy, cloud setup

The toggle to turn on/off TLS is in the config (`tls` field).

### Design Choices
#### Web Framework
Axum is chosen as the framework to serve HTTP and WebSocket requests from the prover clients due to its rich and well supported features, e.g. native integration with Tokio/Hyper/Tower, customizable middleware, the ability to support lower level integrations of TLS ([example](https://github.com/tokio-rs/axum/blob/main/examples/low-level-rustls/src/main.rs)). To simplify the notary server setup, a single Axum router is used to support both HTTP and WebSocket connections, i.e. all requests can be made to the same port of the notary server.

#### WebSocket
Axum's internal implementation of WebSocket uses [tokio_tungstenite](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/), which provides a WebSocket struct that doesn't implement [AsyncRead](https://docs.rs/futures/latest/futures/io/trait.AsyncRead.html) and [AsyncWrite](https://docs.rs/futures/latest/futures/io/trait.AsyncWrite.html). Both these traits are required by the TLSN core libraries for the prover and the notary. To overcome this, a [slight modification](./src/service/axum_websocket.rs) of Axum's implementation of WebSocket is used, where [async_tungstenite](https://docs.rs/async-tungstenite/latest/async_tungstenite/) is used instead so that [ws_stream_tungstenite](https://docs.rs/ws_stream_tungstenite/latest/ws_stream_tungstenite/index.html) can be used to wrap on top of the WebSocket struct to get AsyncRead and AsyncWrite implemented.
