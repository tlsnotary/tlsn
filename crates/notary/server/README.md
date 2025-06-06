# notary-server
An implementation of the notary server in Rust.

## ⚠️ Notice
This crate is currently under active development and should not be used in production. Expect bugs and regular major breaking changes.

---
## Running the server
### ⚠️ Notice
- When running this server against a prover (e.g. [Rust](../../examples/) or [browser extension](https://github.com/tlsnotary/tlsn-extension)), please ensure that the prover's version is the same as the version of this server.
- When running this server in a *production environment*, please first read this [page](https://docs.tlsnotary.org/developers/notary_server.html).

### Using Cargo
Start the server with:
```bash
cargo run --release --bin notary-server
```

### Using Docker
There are two ways to obtain the notary server's Docker image.
- [GitHub](#obtaining-the-image-via-github)
- [Building from source](#building-from-source)

#### GitHub
1. Obtain the latest image.
```bash
docker pull ghcr.io/tlsnotary/tlsn/notary-server:latest
```
2. Run the docker container.
```bash
docker run --init -p 127.0.0.1:7047:7047 ghcr.io/tlsnotary/tlsn/notary-server:latest
```

#### Building from source
1. Build the docker image at the root of this *repository*.
```bash
docker build . -t notary-server:local -f crates/notary/server/notary-server.Dockerfile
```
2. Run the docker container.
```bash
docker run --init -p 127.0.0.1:7047:7047 notary-server:local
```
---
## Configuration
### Default
Refer to [config.rs](./src/config.rs) for more information on the definition of these setting parameters.
```yaml
host: "0.0.0.0"
port: 7047
html_info: |
  <head>
    <meta charset="UTF-8">
    <meta name="author" content="tlsnotary">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body>
    <svg width="86" height="88" viewBox="0 0 86 88" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M25.5484 0.708986C25.5484 0.17436 26.1196 -0.167376 26.5923 0.0844205L33.6891 3.86446C33.9202 3.98756 34.0645 4.22766 34.0645 4.48902V9.44049H37.6129C38.0048 9.44049 38.3226 9.75747 38.3226 10.1485V21.4766L36.1936 20.0606V11.5645H34.0645V80.9919C34.0645 81.1134 34.0332 81.2328 33.9735 81.3388L30.4251 87.6388C30.1539 88.1204 29.459 88.1204 29.1878 87.6388L25.6394 81.3388C25.5797 81.2328 25.5484 81.1134 25.5484 80.9919V0.708986Z" fill="#243F5F"/>
      <path d="M21.2903 25.7246V76.7012H12.7742V34.2207H0V25.7246H21.2903Z" fill="#243F5F"/>
      <path d="M63.871 76.7012H72.3871V34.2207H76.6452V76.7012H85.1613V25.7246H63.871V76.7012Z" fill="#243F5F"/>
      <path d="M38.3226 25.7246H59.6129V34.2207H46.8387V46.9649H59.6129V76.7012H38.3226V68.2051H51.0968V55.4609H38.3226V25.7246Z" fill="#243F5F"/>
    </svg>
    <h1>Notary Server {version}!</h1>
    <ul>
      <li>public key: <pre>{public_key}</pre></li>
      <li>git commit hash: <a href="https://github.com/tlsnotary/tlsn/commit/{git_commit_hash}">{git_commit_hash}</a></li>
      <li><a href="healthcheck">health check</a></li>
      <li><a href="info">info</a></li>
    </ul>
  </body>

concurrency: 32

notarization:
  max_sent_data: 4096
  max_recv_data: 16384
  timeout: 1800
  private_key_path: null
  signature_algorithm: secp256k1

tls:
  enabled: false
  private_key_path: null
  certificate_path: null

log:
  level: DEBUG
  filter: null
  format: COMPACT

auth:
  enabled: false
  whitelist: null
```
⚠️ By default, `notarization.private_key_path` is `null`, which means a **random, ephemeral** signing key will be generated at runtime (see [Signing](#signing) for more details).

### Overriding default
The default setting can be overriden with either (1) environment variables, or (2) a configuration file (yaml).

#### Environment Variables
Default values can be overriden by setting environment variables. The variables have a `NS_`-prefix followed by the configuration key in uppercase. Double underscores are used for nested configuration keys, e.g. `tls.enabled` will be `NS_TLS__ENABLED`.

Example:
```bash
NS_PORT=8080 NS_NOTARIZATION__MAX_SENT_DATA=2048 cargo run --release --bin notary-server
```

##### JWT Claims
Custom user JWT claims can be specified via `NS_AUTH__JWT__CLAIMS=` environment variable where the input format is as follows:

```
NS_AUTH__JWT__CLAIMS="<name> <name>:<value>:...:<value>"
```

Each user claim starts with `<name>` of the claim followed by zero or more values `<value>`, where `:` is used as separator. Therefore, in order to represent a claim:

```yaml
claims:
 - name: sub
   values: ["something"]  
```

one would write `sub:something`.

Next, each user claim is separated by ` `. Therefore, in order to represent claims:

```yaml
claims:
 - name: sub
 - name: custom
   values: ["something"]
```

one would write `NS_AUTH__JWT__CLAIMS="sub custom:something"`.


#### Configuration File
This will override all the default values, hence it needs to **contain all compulsory** configuration keys and values (refer to the [default yaml](#default)). The config file has precedence over environment variables.
```bash
cargo run --release --bin notary-server -- --config <path to your config.yaml>
```

### When using Docker
1. Override the port.
```bash
docker run --init -p 127.0.0.1:7070:7070 -e NS_PORT=7070 notary-server:local
```
2. Override the notarization private key path, and map a local private key into the container.
```bash
docker run --init -p 127.0.0.1:7047:7047 -e NS_NOTARIZATION__PRIVATE_KEY_PATH="/root/.notary/notary.key" -v <your private key>:/root/.notary/notary.key notary-server:local
```
3. Override with a configuration file.
```bash
docker run --init -p 127.0.0.1:7047:7047 -v <your config.yaml>:/root/.notary/config.yaml notary-server:local --config /root/.notary/config.yaml
```
⚠️ The default `workdir` of the container is `/root/.notary`.

---
## API
### HTTP APIs
Defined in the [OpenAPI specification](./openapi.yaml).

### WebSocket APIs
#### /notarize
##### Description
To perform a notarization using a session id — an unique id returned upon calling the `/session` endpoint successfully.

##### Query Parameter
`sessionId`

##### Query Parameter Type
String

---
## Features
### Notarization Configuration
To perform a notarization, some parameters need to be configured by the prover and the notary server (more details in the [OpenAPI specification](./openapi.yaml)), i.e.
- maximum data that can be sent and received.
- unique session id.

To streamline this process, a single HTTP endpoint (`/session`) is used by both TCP and WebSocket clients.

### Notarization
After calling the configuration endpoint above, the prover can proceed to start the notarization. For a TCP client, that means calling the `/notarize` endpoint using HTTP, while a WebSocket client should call the same endpoint but using WebSocket. Example implementations of these clients can be found in the [integration test](../tests-integration/tests/notary.rs).

### Signing
To sign the notarized transcript, the notary server requires a signing key. If this signing key (`notarization.private_key_path` in the config) is not provided by the user, then **by default, a random, ephemeral** signing key will be generated at runtime. 

This ephemeral key, along with its public key, are not persisted. The keys disappear once the server stops. This makes the keys only suitable for testing.

### TLS
TLS needs to be turned on between the prover and the notary for security purposes. It can be turned off though, if any of the following is true.

1. This server is run locally.
2. TLS is to be handled by an external environment, e.g. reverse proxy, cloud setup.

The toggle to turn on TLS, as well as paths to the TLS private key and certificate can be defined in the config (`tls` field).

### Authorization
An optional authorization module is available to only allow requests with a valid credential attached. Currently, two modes are supported: whitelist and JWT.

Please note that only *one* mode can be active at any one time.

#### Whitelist mode
In whitelist mode, a valid API key needs to be attached in the custom HTTP header `X-API-Key`. The path of the API key whitelist, as well as the flag to enable/disable this module, can be changed in the config (`auth` field).

Hot reloading of the whitelist is supported, i.e. changes to the whitelist file are automatically applied without needing to restart the server.

#### JWT mode
In JWT mode, JSON Web Token is attached in the standard `Authorization` HTTP header as a bearer token. The algorithm, the path to verifying key, as well as custom user claims, can be changed in the config (`auth` field).

Care should be taken when defining custom user claims as the middleware will:
- accept any claim if no custom claim is defined,
- as long as user defined claims are found, other unknown claims will be ignored.

An example JWT config may look something like this:

```yaml
auth:
  enabled: true
  jwt:
    algorithm: "RS256"
    public_key_path: "./fixture/auth/jwt.key.pub"
    claims:
      - name: sub
        values: ["tlsnotary"]
```

### Logging
The default logging strategy of this server is set to `DEBUG` verbosity level for the crates that are useful for most debugging scenarios, i.e. using the following filtering logic.

`notary_server=DEBUG,tlsn_verifier=DEBUG,mpc_tls=DEBUG,tls_client_async=DEBUG`

In the configuration, one can toggle the verbosity level for these crates using the `level` field under `logging`.

One can also provide a custom filtering logic by adding a `filter` field under `logging`, and use a value that follows the tracing crate's [filter directive syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax).

Logs can be printed in two formats. Compact and JSON. Compact is human-readable and is best suited for console. JSON is machine-readable and is used to send logs to log collection services. One can change log format by switching the `format` field under `logging`. Accepted values are `COMPACT` and `JSON`. `COMPACT` is used by default.

### Concurrency
One can limit the number of concurrent notarization requests from provers via `concurrency` in the config. This is to limit resource utilization and mitigate potential DoS attacks.

---
## Architecture
### Objective
The main objective of a notary server is to perform notarizations together with a prover. In this case, the prover can either be a
1. TCP client — which has access and control over the transport layer, i.e. TCP.
2. WebSocket client — which has no access over TCP and instead uses WebSocket for notarizations.

### Design Choices
#### Web Framework
Axum is chosen as the framework to serve HTTP and WebSocket requests from the prover clients due to its rich and well supported features, e.g. native integration with Tokio/Hyper/Tower, customizable middleware, the ability to support lower level integrations of TLS ([example](https://github.com/tokio-rs/axum/blob/main/examples/low-level-rustls/src/main.rs)). To simplify the notary server setup, a single Axum router is used to support both HTTP and WebSocket connections, i.e. all requests can be made to the same port of the notary server.

#### WebSocket
Axum's internal implementation of WebSocket uses [tokio_tungstenite](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/), which provides a WebSocket struct that doesn't implement [AsyncRead](https://docs.rs/futures/latest/futures/io/trait.AsyncRead.html) and [AsyncWrite](https://docs.rs/futures/latest/futures/io/trait.AsyncWrite.html). Both these traits are required by the TLSN core libraries for the prover and the notary. To overcome this, a [slight modification](./src/service/axum_websocket.rs) of Axum's implementation of WebSocket is used, where [async_tungstenite](https://docs.rs/async-tungstenite/latest/async_tungstenite/) is used instead so that [ws_stream_tungstenite](https://docs.rs/ws_stream_tungstenite/latest/ws_stream_tungstenite/index.html) can be used to wrap on top of the WebSocket struct to get AsyncRead and AsyncWrite implemented.
