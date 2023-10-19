use axum::{
    http::{Request, StatusCode},
    middleware::from_extractor_with_state,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use eyre::{ensure, eyre, Result};
use futures_util::future::poll_fn;
use hyper::server::{
    accept::Accept,
    conn::{AddrIncoming, Http},
};
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::{
    fs::File as StdFile,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
};

use tokio::{fs::File, net::TcpListener};
use tokio_rustls::TlsAcceptor;
use tower::MakeService;
use tracing::{debug, error, info};

use crate::{
    config::{NotaryServerProperties, NotarySignatureProperties, TLSSignatureProperties},
    domain::{auth::AuthorizationWhitelistRecord, notary::NotaryGlobals, InfoResponse},
    error::NotaryServerError,
    middleware::AuthorizationMiddleware,
    service::{initialize, upgrade_protocol},
    util::parse_csv_file,
};

/// Start a TLS-secured TCP server to accept notarization request for both TCP and WebSocket clients
#[tracing::instrument(skip(config))]
pub async fn run_server(config: &NotaryServerProperties) -> Result<(), NotaryServerError> {
    // Load the private key and cert needed for TLS connection from fixture folder — can be swapped out when we stop using static self signed cert
    let (tls_private_key, tls_certificates) = load_tls_key_and_cert(&config.tls_signature).await?;
    // Load the private key for notarized transcript signing from fixture folder — can be swapped out when we use proper ephemeral signing key
    let notary_signing_key = load_notary_signing_key(&config.notary_signature).await?;
    // Load the authorization whitelist csv if it is turned on
    let authorization_whitelist = if !config.authorization.enabled {
        debug!("Skipping authorization as it is turned off.");
        None
    } else {
        config
            .authorization
            .whitelist_csv_path
            .as_ref()
            .and_then(|path| match parse_csv_file::<AuthorizationWhitelistRecord>(path) {
                Ok(whitelist) => Some(whitelist),
                Err(err) => {
                    debug!("Skipping authorization as we failed to parse authorization whitelist csv: {:?}", err);
                    None
                }
            })
    };

    // Build a TCP listener with TLS enabled
    let mut server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(tls_certificates, tls_private_key)
        .map_err(|err| eyre!("Failed to instantiate notary server tls config: {err}"))?;

    // Set the http protocols we support
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_config = Arc::new(server_config);

    let notary_address = SocketAddr::new(
        IpAddr::V4(config.server.host.parse().map_err(|err| {
            eyre!("Failed to parse notary host address from server config: {err}")
        })?),
        config.server.port,
    );

    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(notary_address)
        .await
        .map_err(|err| eyre!("Failed to bind server address to tcp listener: {err}"))?;
    let mut listener = AddrIncoming::from_listener(listener)
        .map_err(|err| eyre!("Failed to build hyper tcp listener: {err}"))?;

    info!(
        "Listening for TLS-secured TCP traffic at {}",
        notary_address
    );

    let protocol = Arc::new(Http::new());
    let notary_globals = NotaryGlobals::new(
        notary_signing_key,
        config.notarization.clone(),
        authorization_whitelist,
    );

    // Parameters needed for the info endpoint
    let public_key = std::fs::read_to_string(&config.notary_signature.public_key_pem_path)
        .map_err(|err| eyre!("Failed to load notary public signing key for notarization: {err}"))?;
    let version = option_env!("CARGO_PKG_VERSION")
        .unwrap_or("unknown")
        .to_string();
    let router = Router::new()
        .route(
            "/healthcheck",
            get(|| async move { (StatusCode::OK, "Ok").into_response() }),
        )
        .route(
            "/info",
            get(|| async move {
                (
                    StatusCode::OK,
                    Json(InfoResponse {
                        version,
                        public_key,
                    }),
                )
                    .into_response()
            }),
        )
        .route("/session", post(initialize))
        // Not applying auth middleware to /notarize endpoint for now as we can rely on our
        // short-lived session id generated from /session endpoint, as it is not possible
        // to use header for API key for websocket /notarize endpoint due to browser restriction
        // ref: https://stackoverflow.com/a/4361358; And putting it in url query param
        // seems to be more insecured: https://stackoverflow.com/questions/5517281/place-api-key-in-headers-or-url
        .route_layer(from_extractor_with_state::<
            AuthorizationMiddleware,
            NotaryGlobals,
        >(notary_globals.clone()))
        .route("/notarize", get(upgrade_protocol))
        .with_state(notary_globals);
    let mut app = router.into_make_service();

    loop {
        // Poll and await for any incoming connection, ensure that all operations inside are infallible to prevent bringing down the server
        let (prover_address, stream) =
            match poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx)).await {
                Some(Ok(connection)) => (connection.remote_addr(), connection),
                Some(Err(err)) => {
                    error!("{}", NotaryServerError::Connection(err.to_string()));
                    continue;
                }
                None => unreachable!("The poll_accept method should never return None"),
            };
        debug!(?prover_address, "Received a prover's TCP connection");

        let acceptor = acceptor.clone();
        let protocol = protocol.clone();
        let service = MakeService::<_, Request<hyper::Body>>::make_service(&mut app, &stream);

        // Spawn a new async task to handle the new connection
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    info!(
                        ?prover_address,
                        "Accepted prover's TLS-secured TCP connection",
                    );
                    // Serve different requests using the same hyper protocol and axum router
                    let _ = protocol
                        // Can unwrap because it's infallible
                        .serve_connection(stream, service.await.unwrap())
                        // use with_upgrades to upgrade connection to websocket for websocket clients
                        // and to extract tcp connection for tcp clients
                        .with_upgrades()
                        .await;
                }
                Err(err) => {
                    error!(
                        ?prover_address,
                        "{}",
                        NotaryServerError::Connection(err.to_string())
                    );
                }
            }
        });
    }
}

/// Temporary function to load notary signing key from static file
async fn load_notary_signing_key(config: &NotarySignatureProperties) -> Result<SigningKey> {
    debug!("Loading notary server's signing key");

    let notary_signing_key = SigningKey::read_pkcs8_pem_file(&config.private_key_pem_path)
        .map_err(|err| eyre!("Failed to load notary signing key for notarization: {err}"))?;

    debug!("Successfully loaded notary server's signing key!");
    Ok(notary_signing_key)
}

/// Read a PEM-formatted file and return its buffer reader
pub async fn read_pem_file(file_path: &str) -> Result<BufReader<StdFile>> {
    let key_file = File::open(file_path).await?.into_std().await;
    Ok(BufReader::new(key_file))
}

/// Load notary tls private key and cert from static files
async fn load_tls_key_and_cert(
    config: &TLSSignatureProperties,
) -> Result<(PrivateKey, Vec<Certificate>)> {
    debug!("Loading notary server's tls private key and certificate");

    let mut private_key_file_reader = read_pem_file(&config.private_key_pem_path).await?;
    let mut private_keys = rustls_pemfile::pkcs8_private_keys(&mut private_key_file_reader)?;
    ensure!(
        private_keys.len() == 1,
        "More than 1 key found in the tls private key pem file"
    );
    let private_key = PrivateKey(private_keys.remove(0));

    let mut certificate_file_reader = read_pem_file(&config.certificate_pem_path).await?;
    let certificates = rustls_pemfile::certs(&mut certificate_file_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    debug!("Successfully loaded notary server's tls private key and certificate!");
    Ok((private_key, certificates))
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_load_notary_key_and_cert() {
        let config = TLSSignatureProperties {
            private_key_pem_path: "./fixture/tls/notary.key".to_string(),
            certificate_pem_path: "./fixture/tls/notary.crt".to_string(),
        };
        let result: Result<(PrivateKey, Vec<Certificate>)> = load_tls_key_and_cert(&config).await;
        assert!(result.is_ok(), "Could not load tls private key and cert");
    }

    #[tokio::test]
    async fn test_load_notary_signing_key() {
        let config = NotarySignatureProperties {
            private_key_pem_path: "./fixture/notary/notary.key".to_string(),
            public_key_pem_path: "./fixture/notary/notary.pub".to_string(),
        };
        let result: Result<SigningKey> = load_notary_signing_key(&config).await;
        assert!(result.is_ok(), "Could not load notary private key");
    }
}
