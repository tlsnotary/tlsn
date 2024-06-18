//! Notary client.
//!
//! This module sets up connection to notary server via TCP or TLS for subsequent requests for notarization.

use http_body_util::{BodyExt as _, Either, Empty, Full};
use hyper::{body::Bytes, client::conn::http1::Parts, Request, StatusCode};
use hyper_util::rt::TokioIo;
use notary_server::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};
use std::{
    io::Error as IoError,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tlsn_common::config::{DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore},
    TlsConnector,
};
use tracing::{debug, error};

use crate::error::{ClientError, ErrorKind};

/// Parameters used to configure notarization.
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct NotarizationRequest {
    /// Maximum number of bytes that can be sent.
    #[builder(default = "DEFAULT_MAX_SENT_LIMIT")]
    max_sent_data: usize,
    /// Maximum number of bytes that can be received.
    #[builder(default = "DEFAULT_MAX_RECV_LIMIT")]
    max_recv_data: usize,
}

impl NotarizationRequest {
    /// Creates a new builder for `NotarizationRequest`.
    pub fn builder() -> NotarizationRequestBuilder {
        NotarizationRequestBuilder::default()
    }
}

/// An accepted notarization request.
#[derive(Debug)]
#[non_exhaustive]
pub struct Accepted {
    /// Session identifier.
    pub id: String,
    /// Connection to the notary server to be used by a prover.
    pub io: NotaryConnection,
}

/// A notary server connection.
#[derive(Debug)]
pub enum NotaryConnection {
    /// Unencrypted TCP connection.
    Tcp(TcpStream),
    /// TLS connection.
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for NotaryConnection {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), IoError>> {
        match self.get_mut() {
            NotaryConnection::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            NotaryConnection::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for NotaryConnection {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        match self.get_mut() {
            NotaryConnection::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            NotaryConnection::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        match self.get_mut() {
            NotaryConnection::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            NotaryConnection::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        match self.get_mut() {
            NotaryConnection::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            NotaryConnection::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Client that sets up connection to notary server.
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct NotaryClient {
    /// Host of the notary server endpoint, either a DNS name (if TLS is used) or IP address.
    #[builder(setter(into))]
    host: String,
    /// Port of the notary server endpoint.
    #[builder(default = "self.default_port()")]
    port: u16,
    /// Flag to turn on/off using TLS with notary server.
    #[builder(setter(name = "enable_tls"), default = "true")]
    tls: bool,
    /// Root certificate store used for establishing TLS connection with notary server.
    #[builder(default = "default_root_store()")]
    root_cert_store: RootCertStore,
    /// API key used to call notary server endpoints if whitelisting is enabled in notary server.
    #[builder(setter(into, strip_option), default)]
    api_key: Option<String>,
}

impl NotaryClientBuilder {
    // Default setter of port.
    fn default_port(&self) -> u16 {
        // If port is not specified, set it to 80 if TLS is off, else 443 since TLS is on
        // (including when self.tls = None, which means it's set to default (true)).
        if let Some(false) = self.tls {
            80
        } else {
            443
        }
    }
}

impl NotaryClient {
    /// Creates a new builder for `NotaryClient`.
    pub fn builder() -> NotaryClientBuilder {
        NotaryClientBuilder::default()
    }

    /// Configures and requests a notarization, returning a connection to the notary server if successful.
    pub async fn request_notarization(
        &self,
        notarization_request: NotarizationRequest,
    ) -> Result<Accepted, ClientError> {
        if self.tls {
            debug!("Setting up tls connection...");

            let notary_client_config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(self.root_cert_store.clone())
                .with_no_client_auth();

            let notary_socket = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|err| ClientError::new(ErrorKind::Connection, Some(Box::new(err))))?;

            let notary_connector = TlsConnector::from(Arc::new(notary_client_config));
            let notary_tls_socket = notary_connector
                .connect(
                    self.host.as_str().try_into().map_err(|err| {
                        error!("Failed to parse notary server DNS name: {:?}", self.host);
                        ClientError::new(ErrorKind::TlsSetup, Some(Box::new(err)))
                    })?,
                    notary_socket,
                )
                .await
                .map_err(|err| ClientError::new(ErrorKind::TlsSetup, Some(Box::new(err))))?;

            self.send_request(notary_tls_socket, notarization_request)
                .await
                .map(|(connection, session_id)| Accepted {
                    id: session_id,
                    io: NotaryConnection::Tls(connection),
                })
        } else {
            debug!("Setting up tcp connection...");

            let notary_socket = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|err| ClientError::new(ErrorKind::Connection, Some(Box::new(err))))?;

            self.send_request(notary_socket, notarization_request)
                .await
                .map(|(connection, session_id)| Accepted {
                    id: session_id,
                    io: NotaryConnection::Tcp(connection),
                })
        }
    }

    /// Sends notarization request to the notary server.
    async fn send_request<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        &self,
        notary_socket: S,
        notarization_request: NotarizationRequest,
    ) -> Result<(S, String), ClientError> {
        let http_scheme = if self.tls { "https" } else { "http" };

        // Attach the hyper HTTP client to the notary connection to send request to the /session endpoint to configure notarization and obtain session id.
        let (mut notary_request_sender, notary_connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(notary_socket))
                .await
                .map_err(|err| {
                    error!("Failed to attach http client to notary socket");
                    ClientError::new(ErrorKind::Connection, Some(Box::new(err)))
                })?;

        // Create a future to poll the notary connection to completion before extracting the socket.
        let notary_connection_fut = async {
            // Claim back notary socket after HTTP exchange is done.
            let Parts {
                io: notary_socket, ..
            } = notary_connection.without_shutdown().await.map_err(|err| {
                error!("Failed to claim back notary socket after HTTP exchange is done");
                ClientError::new(ErrorKind::Internal, Some(Box::new(err)))
            })?;

            Ok(notary_socket)
        };

        // Create a future to send configuration and notarization requests to the notary server using the connection established above.
        let client_requests_fut = async {
            // Build the HTTP request to configure notarization.
            let configuration_request_payload =
                serde_json::to_string(&NotarizationSessionRequest {
                    client_type: ClientType::Tcp,
                    max_sent_data: Some(notarization_request.max_sent_data),
                    max_recv_data: Some(notarization_request.max_recv_data),
                })
                .map_err(|err| {
                    error!("Failed to serialise http request for configuration");
                    ClientError::new(ErrorKind::Internal, Some(Box::new(err)))
                })?;

            let mut configuration_request_builder = Request::builder()
                .uri(format!(
                    "{http_scheme}://{}:{}/session",
                    self.host, self.port
                ))
                .method("POST")
                .header("Host", &self.host)
                // Need to specify application/json for axum to parse it as json.
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
                    error!("Failed to build http request for configuration");
                    ClientError::new(ErrorKind::Internal, Some(Box::new(err)))
                })?;

            debug!("Sending configuration request: {:?}", configuration_request);

            let configuration_response = notary_request_sender
                .send_request(configuration_request)
                .await
                .map_err(|err| {
                    error!("Failed to send http request for configuration");
                    ClientError::new(ErrorKind::Http, Some(Box::new(err)))
                })?;

            debug!("Sent configuration request");

            if configuration_response.status() != StatusCode::OK {
                return Err(ClientError::new(
                    ErrorKind::Configuration,
                    Some(
                        format!(
                            "Configuration response status is not OK: {:?}",
                            configuration_response
                        )
                        .into(),
                    ),
                ));
            }

            let configuration_response_payload = configuration_response
                .into_body()
                .collect()
                .await
                .map_err(|err| {
                    error!("Failed to parse configuration response");
                    ClientError::new(ErrorKind::Http, Some(Box::new(err)))
                })?
                .to_bytes();

            let configuration_response_payload_parsed =
                serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(
                    &configuration_response_payload,
                ))
                .map_err(|err| {
                    error!("Failed to parse configuration response payload");
                    ClientError::new(ErrorKind::Internal, Some(Box::new(err)))
                })?;

            debug!(
                "Configuration response: {:?}",
                configuration_response_payload_parsed
            );

            // Send notarization request via HTTP, where the underlying TCP/TLS connection will be extracted later.
            let notarization_request = Request::builder()
                // Need to specify the session_id so that notary server knows the right configuration to use
                // as the configuration is set in the previous HTTP call.
                .uri(format!(
                    "{http_scheme}://{}:{}/notarize?sessionId={}",
                    self.host, self.port, &configuration_response_payload_parsed.session_id
                ))
                .method("GET")
                .header("Host", &self.host)
                .header("Connection", "Upgrade")
                // Need to specify this upgrade header for server to extract TCP/TLS connection later.
                .header("Upgrade", "TCP")
                .body(Either::Right(Empty::<Bytes>::new()))
                .map_err(|err| {
                    error!("Failed to build http request for notarization");
                    ClientError::new(ErrorKind::Internal, Some(Box::new(err)))
                })?;

            debug!("Sending notarization request: {:?}", notarization_request);

            let notarization_response = notary_request_sender
                .send_request(notarization_request)
                .await
                .map_err(|err| {
                    error!("Failed to send http request for notarization");
                    ClientError::new(ErrorKind::Http, Some(Box::new(err)))
                })?;

            debug!("Sent notarization request");

            if notarization_response.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(ClientError::new(
                    ErrorKind::Internal,
                    Some(
                        format!(
                            "Notarization response status is not SWITCHING_PROTOCOL: {:?}",
                            notarization_response
                        )
                        .into(),
                    ),
                ));
            }

            Ok(configuration_response_payload_parsed.session_id)
        };

        // Poll both futures simultaneously to obtain the resulting socket and session_id.
        let (notary_socket, session_id) =
            futures::try_join!(notary_connection_fut, client_requests_fut)?;

        Ok((notary_socket.into_inner(), session_id))
    }
}

/// Default root store using mozilla certs.
fn default_root_store() -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));

    root_store
}
