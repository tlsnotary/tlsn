//! Notary client
//!
//! This module sets up prover to connect to notary via TCP or TLS

use eyre::eyre;
use http_body_util::{BodyExt as _, Either, Empty, Full};
use hyper::{client::conn::http1::Parts, Request, StatusCode};
use hyper_util::rt::TokioIo;
use notary_server::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};
use rustls::{Certificate, ClientConfig, RootCertStore};
use std::sync::Arc;
use tls_client::RootCertStore as TlsClientRootCertStore;
use tlsn_common::config::{DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT};
use tlsn_prover::tls::{state::Setup, Prover, ProverConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_util::{bytes::Bytes, compat::TokioAsyncReadCompatExt};

#[cfg(feature = "tracing")]
use tracing::debug;

use crate::error::NotaryClientError;

/// Client that setup prover to connect to notary server
#[derive(Debug, Clone, derive_builder::Builder)]
#[builder(build_fn(error = "NotaryClientError"))]
pub struct NotaryClient {
    /// Host of the notary server endpoint
    #[builder(setter(into))]
    host: String,
    /// Port of the notary server endpoint
    port: u16,
    /// Maximum number of bytes that can be sent.
    #[builder(default = "DEFAULT_MAX_SENT_LIMIT")]
    max_sent_data: usize,
    /// Maximum number of bytes that can be received.
    #[builder(default = "DEFAULT_MAX_RECV_LIMIT")]
    max_recv_data: usize,
    /// Root certificate store used for establishing TLS connection with notary
    #[builder(default = "Some(notary_default_root_store()?)")]
    notary_root_cert_store: Option<RootCertStore>,
    /// DNS name of notary server used for establishing TLS connection with notary
    #[builder(setter(into), default = "Some(\"tlsnotaryserver.io\".to_string())")]
    notary_dns: Option<String>,
    /// API key used to call notary server endpoints if whitelisting is enabled in notary server
    #[builder(setter(into, strip_option), default)]
    api_key: Option<String>,
    /// TLS root certificate store
    #[builder(default = "server_default_root_store()")]
    server_root_cert_store: TlsClientRootCertStore,
    /// Application server DNS name
    #[builder(setter(into))]
    server_dns: String,
}

impl NotaryClient {
    /// Create a new builder for `NotaryClient`.
    pub fn builder() -> NotaryClientBuilder {
        NotaryClientBuilder::default()
    }

    /// Returns a prover that connects to notary via TCP without TLS
    pub async fn setup_tcp_prover(&self) -> Result<Prover<Setup>, NotaryClientError> {
        #[cfg(feature = "tracing")]
        debug!("Setting up tcp connection...");
        let notary_socket = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|err| NotaryClientError::Connection(err.to_string()))?;

        self.request_notarization(notary_socket).await
    }

    /// Returns a prover that connects to notary via TCP-TLS
    pub async fn setup_tls_prover(&self) -> Result<Prover<Setup>, NotaryClientError> {
        #[cfg(feature = "tracing")]
        debug!("Setting up tls connection...");
        let notary_root_cert_store =
            self.notary_root_cert_store
                .clone()
                .ok_or(NotaryClientError::TlsSetup(
                    "Notary root cert store is not provided".to_string(),
                ))?;
        let notary_dns = self.notary_dns.as_ref().ok_or(NotaryClientError::TlsSetup(
            "Notary dns is not provided".to_string(),
        ))?;

        let notary_socket = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|err| NotaryClientError::Connection(err.to_string()))?;

        let client_notary_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(notary_root_cert_store)
            .with_no_client_auth();

        let notary_connector = TlsConnector::from(Arc::new(client_notary_config));
        let notary_tls_socket = notary_connector
            .connect(
                notary_dns.as_str().try_into().map_err(|err| {
                    NotaryClientError::TlsSetup(format!("Failed to parse notary dns: {err}"))
                })?,
                notary_socket,
            )
            .await
            .map_err(|err| {
                NotaryClientError::TlsSetup(format!("Failed to connect to notary via TLS: {err}"))
            })?;

        self.request_notarization(notary_tls_socket).await
    }

    /// Requests notarization from the Notary server.
    async fn request_notarization<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        &self,
        notary_socket: S,
    ) -> Result<Prover<Setup>, NotaryClientError> {
        let http_scheme = if self.notary_dns.is_some() {
            "https"
        } else {
            "http"
        };

        // Attach the hyper HTTP client to the notary connection to send request to the /session endpoint to configure notarization and obtain session id
        let (mut notary_request_sender, notary_connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(notary_socket))
                .await
                .map_err(|err| {
                    NotaryClientError::Connection(format!(
                        "Failed to attach http client to notary socket: {err}"
                    ))
                })?;

        // Spawn the HTTP task to be run concurrently
        let notary_connection_task = tokio::spawn(notary_connection.without_shutdown());

        // Build the HTTP request to configure notarization
        let configuration_request_payload = serde_json::to_string(&NotarizationSessionRequest {
            client_type: ClientType::Tcp,
            max_sent_data: Some(self.max_sent_data),
            max_recv_data: Some(self.max_recv_data),
        })
        .map_err(|err| {
            NotaryClientError::Configuration(format!(
                "Failed to serialise http request for configuration: {err}"
            ))
        })?;

        let mut configuration_request_builder = Request::builder()
            .uri(format!(
                "{http_scheme}://{}:{}/session",
                self.host, self.port
            ))
            .method("POST")
            .header("Host", &self.host)
            // Need to specify application/json for axum to parse it as json
            .header("Content-Type", "application/json");

        if let Some(api_key) = &self.api_key {
            configuration_request_builder =
                configuration_request_builder.header("Authorization", api_key);
        }

        let configuration_request = configuration_request_builder
            .body(Either::Left(Full::new(Bytes::from(
                configuration_request_payload,
            ))))
            .map_err(|err| {
                NotaryClientError::Configuration(format!(
                    "Failed to build http request for configuration: {err}"
                ))
            })?;

        #[cfg(feature = "tracing")]
        debug!("Sending configuration request: {:?}", configuration_request);

        let configuration_response = notary_request_sender
            .send_request(configuration_request)
            .await
            .map_err(|err| {
                NotaryClientError::Configuration(format!(
                    "Failed to send http request for configuration: {err}"
                ))
            })?;

        #[cfg(feature = "tracing")]
        debug!("Sent configuration request");

        if configuration_response.status() != StatusCode::OK {
            return Err(NotaryClientError::Configuration(format!(
                "Configuration response is not OK: {:?}",
                configuration_response
            )));
        }

        let configuration_response_payload = configuration_response
            .into_body()
            .collect()
            .await
            .map_err(|err| {
                NotaryClientError::Configuration(format!(
                    "Failed to parse configuration response: {err}"
                ))
            })?
            .to_bytes();

        let configuration_response_payload_parsed =
            serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(
                &configuration_response_payload,
            ))
            .map_err(|err| {
                NotaryClientError::Configuration(format!(
                    "Failed to parse configuration response: {err}"
                ))
            })?;

        #[cfg(feature = "tracing")]
        debug!(
            "Configuration response: {:?}",
            configuration_response_payload_parsed
        );

        // Send notarization request via HTTP, where the underlying TCP/TLS connection will be extracted later
        let notarization_request = Request::builder()
            // Need to specify the session_id so that notary server knows the right configuration to use
            // as the configuration is set in the previous HTTP call
            .uri(format!(
                "{http_scheme}://{}:{}/notarize?sessionId={}",
                self.host, self.port, &configuration_response_payload_parsed.session_id
            ))
            .method("GET")
            .header("Host", &self.host)
            .header("Connection", "Upgrade")
            // Need to specify this upgrade header for server to extract TCP/TLS connection later
            .header("Upgrade", "TCP")
            .body(Either::Right(Empty::<Bytes>::new()))
            .map_err(|err| {
                NotaryClientError::NotarizationRequest(format!(
                    "Failed to build http request for notarization: {err}"
                ))
            })?;

        #[cfg(feature = "tracing")]
        debug!("Sending notarization request: {:?}", notarization_request);

        let notarization_response = notary_request_sender
            .send_request(notarization_request)
            .await
            .map_err(|err| {
                NotaryClientError::NotarizationRequest(format!(
                    "Failed to send http request for notarization: {err}"
                ))
            })?;

        #[cfg(feature = "tracing")]
        debug!("Sent notarization request");

        if notarization_response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(NotaryClientError::NotarizationRequest(format!(
                "Notarization response is not SWITCHING_PROTOCOL: {:?}",
                notarization_response
            )));
        }

        // Claim back notary socket after HTTP exchange is done
        let Parts {
            io: notary_socket, ..
        } = notary_connection_task
            .await
            .map_err(|err| eyre!("Error when joining notary connection task: {err}"))?
            .map_err(|err| {
                eyre!("Failed to claim back notary socket after HTTP exchange is done: {err}")
            })?;

        #[cfg(feature = "tracing")]
        debug!("Setting up prover...");

        // Basic default prover config using the session_id returned from /session endpoint just now
        let prover_config = ProverConfig::builder()
            .id(configuration_response_payload_parsed.session_id)
            .server_dns(&self.server_dns)
            .max_sent_data(self.max_sent_data)
            .max_recv_data(self.max_recv_data)
            .root_cert_store(self.server_root_cert_store.clone())
            .build()?;

        // Create a new prover
        let prover = Prover::new(prover_config)
            .setup(notary_socket.into_inner().compat())
            .await?;

        Ok(prover)
    }
}

/// Default root store using mozilla certs.
fn server_default_root_store() -> TlsClientRootCertStore {
    let mut root_store = TlsClientRootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));

    root_store
}

/// Default root store using self signed certs.
fn notary_default_root_store() -> Result<RootCertStore, NotaryClientError> {
    let pem_file = std::str::from_utf8(include_bytes!(
        "../../../notary/server/fixture/tls/rootCA.crt"
    ))
    .map_err(|err| {
        NotaryClientError::Builder(format!("Failed to parse default root CA cert: {err}"))
    })?;

    let mut reader = std::io::BufReader::new(pem_file.as_bytes());
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut reader)
        .map_err(|err| {
            NotaryClientError::Builder(format!("Failed to setup default root CA cert: {err}"))
        })?
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_store = RootCertStore::empty();
    root_store.add(&certificate).map_err(|err| {
        NotaryClientError::Builder(format!(
            "Fialed to add default root cert to root store: {err}"
        ))
    })?;

    Ok(root_store)
}
