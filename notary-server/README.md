# notary-server

An implementation of the notary server in Rust.

## ⚠️ Notice

This crate is currently under active development and should not be used in production. Expect bugs and regular major breaking changes.

---
## Running the server
⚠️ To run this server in a *production environment*, please first read this [page](https://docs.tlsnotary.org/developers/notary_server.html).

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

⚠️ When running this notary-server image against a [prover](https://github.com/tlsnotary/tlsn/tree/3e0dcc77d5b8b7d6739ca725f36345108ebecd75/tlsn/examples), please ensure that the prover's tagged version is the same as the version tag of this image.

#### Building from source
1. Configure the server setting in this config [file](./config/config.yaml).
2. Build the docker image by running the following in a terminal at the root of this *repository*.
```bash
docker build . -t notary-server:local -f notary-server/notary-server.Dockerfile
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
- Example 2: Using different key for notarization:
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
To perform notarization using the session id (unique id returned upon calling the `/session` endpoint successfully).

##### Query Parameter
`sessionId`

##### Query Parameter Type
String

---
## Architecture
### Objective
The main objective of a notary server is to perform notarization together with a prover. In this case, the prover can either be
1. TCP client — which has access and control over the transport layer, i.e. TCP
2. WebSocket client — which has no access over TCP and instead uses WebSocket for notarization

### Features
#### Notarization Configuration
To perform notarization, some parameters need to be configured by the prover and notary server (more details in the [OpenAPI specification](./openapi.yaml)), i.e.
- maximum transcript size
- unique session id

To streamline this process, a single HTTP endpoint (`/session`) is used by both TCP and WebSocket clients.

#### Notarization
After calling the configuration endpoint above, prover can proceed to start notarization. For TCP client, that means calling the `/notarize` endpoint using HTTP (`https`), while WebSocket client should call the same endpoint but using WebSocket (`wss`). Example implementations of these clients can be found in the [integration test](./tests/integration_test.rs).

#### Signatures
Currently, both the private key (and cert) used to establish TLS connection with prover, and the private key used by notary server to sign the notarized transcript, are hardcoded PEM keys stored in this repository. Though the paths of these keys can be changed in the config to use different keys instead.

#### Authorization
An optional authorization module is available to only allow requests with valid API key attached in the authorization header. The API key whitelist path (as well as the flag to enable/disable this module) is configurable [here](./config/config.yaml).

#### Optional TLS
TLS between prover and notary is currently manually handled in the server, though it can be turned off if TLS is to be handled by an external environment, e.g. reverse proxy, cloud setup (configurable [here](./config/config.yaml)).

### Design Choices
#### Web Framework
Axum is chosen as the framework to serve HTTP and WebSocket requests from the prover clients due to its rich and well supported features, e.g. native integration with Tokio/Hyper/Tower, customizable middleware, ability to support lower level integration of TLS ([example](https://github.com/tokio-rs/axum/blob/main/examples/low-level-rustls/src/main.rs)). To simplify the notary server setup, a single Axum router is used to support both HTTP and WebSocket connections, i.e. all requests can be made to the same port of the notary server.

#### WebSocket
Axum's internal implementation of WebSocket uses [tokio_tungstenite](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/), which provides a WebSocket struct that doesn't implement [AsyncRead](https://docs.rs/futures/latest/futures/io/trait.AsyncRead.html) and [AsyncWrite](https://docs.rs/futures/latest/futures/io/trait.AsyncWrite.html). Both these traits are required by TLSN core libraries for prover and notary. To overcome this, a [slight modification](./src/service/axum_websocket.rs) of Axum's implementation of WebSocket is used, where [async_tungstenite](https://docs.rs/async-tungstenite/latest/async_tungstenite/) is used instead so that [ws_stream_tungstenite](https://docs.rs/ws_stream_tungstenite/latest/ws_stream_tungstenite/index.html) can be used to wrap on top of the WebSocket struct to get AsyncRead and AsyncWrite implemented.
