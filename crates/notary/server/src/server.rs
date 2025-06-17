use axum::{
    extract::Request,
    http::StatusCode,
    middleware::from_extractor_with_state,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use eyre::{ensure, eyre, Result};
use futures_util::future::poll_fn;
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use pkcs8::DecodePrivateKey;
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::{
    fs::File as StdFile,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
};
use tlsn_core::CryptoProvider;
use tokio::{fs::File, io::AsyncReadExt, net::TcpListener};
use tokio_rustls::{rustls, TlsAcceptor};
use tower_http::cors::CorsLayer;
use tower_service::Service;
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

use crate::{
    auth::{load_authorization_mode, watch_and_reload_authorization_whitelist, AuthorizationMode}, config::{NotarizationProperties, NotaryServerProperties}, error::NotaryServerError, middleware::AuthorizationMiddleware, plugin::get_plugin_names, service::{initialize, upgrade_protocol}, signing::AttestationKey, types::{InfoResponse, NotaryGlobals}
};

#[cfg(feature = "tee_quote")]
use crate::tee::quote;

use tokio::sync::Semaphore;

/// Start a TCP server (with or without TLS) to accept notarization request for
/// both TCP and WebSocket clients
#[tracing::instrument(skip(config))]
pub async fn run_server(config: &NotaryServerProperties) -> Result<(), NotaryServerError> {
    // Get plugin names
    let plugin_names = get_plugin_names(&config.plugin.folder)?;
    debug!("Available plugins: {:?}", plugin_names);

    let attestation_key = get_attestation_key(&config.notarization).await?;
    let verifying_key_pem = attestation_key
        .verifying_key_pem()
        .map_err(|err| eyre!("Failed to get verifying key in PEM format: {err}"))?;

    #[cfg(feature = "tee_quote")]
    let verifying_key_bytes = attestation_key.verifying_key_bytes();

    let crypto_provider = build_crypto_provider(attestation_key);

    // Build TLS acceptor if it is turned on
    let tls_acceptor = if !config.tls.enabled {
        debug!("Skipping TLS setup as it is turned off.");
        None
    } else {
        let private_key_pem_path = config
            .tls
            .private_key_path
            .as_deref()
            .ok_or_else(|| eyre!("TLS is enabled but private key PEM path is not set"))?;
        let certificate_pem_path = config
            .tls
            .certificate_path
            .as_deref()
            .ok_or_else(|| eyre!("TLS is enabled but certificate PEM path is not set"))?;

        let (tls_private_key, tls_certificates) =
            load_tls_key_and_cert(private_key_pem_path, certificate_pem_path).await?;

        let mut server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(tls_certificates, tls_private_key)
            .map_err(|err| eyre!("Failed to instantiate notary server tls config: {err}"))?;

        // Set the http protocols we support
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_config = Arc::new(server_config);
        Some(TlsAcceptor::from(tls_config))
    };

    // Set up authorization if it is turned on
    let authorization_mode = load_authorization_mode(config).await?;
    // Enable hot reload if authorization whitelist is available
    let watcher = authorization_mode
        .as_ref()
        .and_then(AuthorizationMode::as_whitelist)
        .map(watch_and_reload_authorization_whitelist)
        .transpose()?;
    if watcher.is_some() {
        debug!("Successfully setup watcher for hot reload of authorization whitelist!");
    }

    let notary_address = SocketAddr::new(
        IpAddr::V4(config.host.parse().map_err(|err| {
            eyre!("Failed to parse notary host address from server config: {err}")
        })?),
        config.port,
    );
    let mut listener = TcpListener::bind(notary_address)
        .await
        .map_err(|err| eyre!("Failed to bind server address to tcp listener: {err}"))?;

    info!("Listening for TCP traffic at {}", notary_address);

    let protocol = Arc::new(http1::Builder::new());
    let notary_globals = NotaryGlobals::new(
        Arc::new(crypto_provider),
        config.notarization.clone(),
        config.plugin.clone(),
        Arc::new(plugin_names.clone()),
        authorization_mode,
        Arc::new(Semaphore::new(config.concurrency)),
    );

    // Parameters needed for the info endpoint
    let version = env!("CARGO_PKG_VERSION").to_string();
    let git_commit_hash = env!("GIT_COMMIT_HASH").to_string();

    // Parameters needed for the root / endpoint
    let html_string = config.html_info.clone();
    let html_info = Html(
        html_string
            .replace("{version}", &version)
            .replace("{git_commit_hash}", &git_commit_hash)
            .replace("{public_key}", &verifying_key_pem),
    );

    let router = Router::new()
        .route(
            "/",
            get(|| async move { (StatusCode::OK, html_info).into_response() }),
        )
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
                        public_key: verifying_key_pem,
                        git_commit_hash,
                        plugin_names,
                        #[cfg(feature = "tee_quote")]
                        quote: quote(verifying_key_bytes).await,
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
        .layer(CorsLayer::permissive())
        .with_state(notary_globals);

    loop {
        // Poll and await for any incoming connection, ensure that all operations inside
        // are infallible to prevent bringing down the server
        let stream = match poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx)).await {
            Ok((stream, _)) => stream,
            Err(err) => {
                error!("{}", NotaryServerError::Connection(err.to_string()));
                continue;
            }
        };
        debug!("Received a prover's TCP connection");

        let tower_service = router.clone();
        let tls_acceptor = tls_acceptor.clone();
        let protocol = protocol.clone();

        // Spawn a new async task to handle the new connection
        tokio::spawn(async move {
            // When TLS is enabled
            if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(stream) => {
                        info!("Accepted prover's TLS-secured TCP connection");
                        // Reference: https://github.com/tokio-rs/axum/blob/5201798d4e4d4759c208ef83e30ce85820c07baa/examples/low-level-rustls/src/main.rs#L67-L80
                        let io = TokioIo::new(stream);
                        let hyper_service =
                            hyper::service::service_fn(move |request: Request<Incoming>| {
                                tower_service.clone().call(request)
                            });
                        // Serve different requests using the same hyper protocol and axum router
                        let _ = protocol
                            .serve_connection(io, hyper_service)
                            // use with_upgrades to upgrade connection to websocket for websocket
                            // clients and to extract tcp connection for
                            // tcp clients
                            .with_upgrades()
                            .await;
                    }

                    Err(err) => {
                        error!("{}", NotaryServerError::Connection(err.to_string()));

                        if let Some(rustls::Error::InvalidMessage(
                            rustls::InvalidMessage::InvalidContentType,
                        )) = err
                            .get_ref()
                            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                        {
                            error!("Perhaps the client is connecting without TLS");
                        }
                    }
                }
            } else {
                // When TLS is disabled
                info!("Accepted prover's TCP connection",);
                // Reference: https://github.com/tokio-rs/axum/blob/5201798d4e4d4759c208ef83e30ce85820c07baa/examples/low-level-rustls/src/main.rs#L67-L80
                let io = TokioIo::new(stream);
                let hyper_service =
                    hyper::service::service_fn(move |request: Request<Incoming>| {
                        tower_service.clone().call(request)
                    });
                // Serve different requests using the same hyper protocol and axum router
                let _ = protocol
                    .serve_connection(io, hyper_service)
                    // use with_upgrades to upgrade connection to websocket for websocket clients
                    // and to extract tcp connection for tcp clients
                    .with_upgrades()
                    .await;
            }
        });
    }
}

fn build_crypto_provider(attestation_key: AttestationKey) -> CryptoProvider {
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(attestation_key.into_signer());
    provider
}

/// Get notary signing key for attestations.
/// Generate a random key if user does not provide a static key.
async fn get_attestation_key(config: &NotarizationProperties) -> Result<AttestationKey> {
    let key = if let Some(private_key_path) = &config.private_key_path {
        debug!("Loading notary server's signing key");

        let mut file = File::open(private_key_path).await?;
        let mut pem = String::new();
        file.read_to_string(&mut pem)
            .await
            .map_err(|_| eyre!("pem file does not contain valid UTF-8"))?;

        let key = AttestationKey::from_pkcs8_pem(&pem)
            .map_err(|err| eyre!("Failed to load notary signing key for notarization: {err}"))?;

        pem.zeroize();

        key
    } else {
        warn!(
            "⚠️ Using a random, ephemeral signing key because `notarization.private_key_path` is not set."
        );
        AttestationKey::random(&config.signature_algorithm)?
    };

    Ok(key)
}

/// Read a PEM-formatted file and return its buffer reader
pub async fn read_pem_file(file_path: &str) -> Result<BufReader<StdFile>> {
    let key_file = File::open(file_path).await?.into_std().await;
    Ok(BufReader::new(key_file))
}

/// Load notary tls private key and cert from static files
async fn load_tls_key_and_cert(
    private_key_pem_path: &str,
    certificate_pem_path: &str,
) -> Result<(PrivateKey, Vec<Certificate>)> {
    debug!("Loading notary server's tls private key and certificate");

    let mut private_key_file_reader = read_pem_file(private_key_pem_path).await?;
    let mut private_keys = rustls_pemfile::pkcs8_private_keys(&mut private_key_file_reader)?;
    ensure!(
        private_keys.len() == 1,
        "More than 1 key found in the tls private key pem file"
    );
    let private_key = PrivateKey(private_keys.remove(0));

    let mut certificate_file_reader = read_pem_file(certificate_pem_path).await?;
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
    async fn test_load_tls_key_and_cert() {
        let private_key_pem_path = "../tests-integration/fixture/tls/notary.key";
        let certificate_pem_path = "../tests-integration/fixture/tls/notary.crt";
        let result: Result<(PrivateKey, Vec<Certificate>)> =
            load_tls_key_and_cert(private_key_pem_path, certificate_pem_path).await;
        assert!(result.is_ok(), "Could not load tls private key and cert");
    }

    #[tokio::test]
    async fn test_load_attestation_key() {
        let config = NotarizationProperties {
            private_key_path: Some("../tests-integration/fixture/notary/notary.key".to_string()),
            ..Default::default()
        };
        let result = get_attestation_key(&config).await;
        assert!(result.is_ok(), "Could not load attestation key");
    }

    #[tokio::test]
    async fn test_generate_attestation_key() {
        let config = NotarizationProperties {
            private_key_path: None,
            ..Default::default()
        };
        let result = get_attestation_key(&config).await;
        assert!(result.is_ok(), "Could not generate attestation key");
    }
}
