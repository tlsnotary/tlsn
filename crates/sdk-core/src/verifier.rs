//! SDK Verifier implementation.

use tlsn::{
    config::tls_commit::{TlsCommitRequest, mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    connection::{ConnectionInfo, ServerName, TranscriptLength},
    transcript::ContentType,
    verifier::{state, Verifier},
    webpki::RootCertStore,
    Session, SessionHandle,
};
use tracing::info;

use crate::{
    config::VerifierConfig,
    error::{Result, SdkError},
    io::Io,
    types::VerifierOutput,
};

/// SDK Verifier for TLSNotary protocol.
///
/// The verifier participates in the MPC-TLS protocol with the prover,
/// verifying the authenticity of the TLS session without seeing the
/// full plaintext.
pub struct SdkVerifier {
    config: VerifierConfig,
    state: State,
}

#[allow(clippy::large_enum_variant)]
enum State {
    Initialized,
    Connected {
        verifier: Verifier<state::Initialized>,
        handle: SessionHandle,
    },
    AcceptedMpc {
        verifier: Verifier<state::CommitAccepted<MpcTlsConfig>>,
        handle: SessionHandle,
    },
    AcceptedProxy {
        verifier: Verifier<state::CommitAccepted<ProxyTlsConfig>>,
        handle: SessionHandle,
        server_socket: Option<Box<dyn Io>>,
    },
    Committed {
        verifier: Verifier<state::Committed>,
        handle: SessionHandle,
    },
    Complete,
    Error,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Initialized => write!(f, "Initialized"),
            State::Connected { .. } => write!(f, "Connected"),
            State::AcceptedMpc { .. } => write!(f, "AcceptedMpc"),
            State::AcceptedProxy { .. } => write!(f, "AcceptedProxy"),
            State::Committed { .. } => write!(f, "Committed"),
            State::Complete => write!(f, "Complete"),
            State::Error => write!(f, "Error"),
        }
    }
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

impl SdkVerifier {
    /// Creates a new SDK Verifier with the given configuration.
    pub fn new(config: VerifierConfig) -> Self {
        SdkVerifier {
            state: State::Initialized,
            config,
        }
    }

    /// Connects to the prover.
    ///
    /// # Arguments
    ///
    /// * `prover_io` - A duplex IO stream connected to the prover.
    pub async fn connect(&mut self, prover_io: impl Io) -> Result<()> {
        let State::Initialized = self.state.take() else {
            return Err(SdkError::invalid_state(
                "verifier is not in initialized state",
            ));
        };

        info!("connecting to prover");

        let session = Session::new(prover_io);
        let (driver, mut handle) = session.split();

        crate::spawn::spawn(async move {
            match driver.await {
                Ok(_io) => tracing::warn!("session driver completed (mux closed)"),
                Err(e) => tracing::error!("session driver error: {e}"),
            }
        });

        let builder =
            tlsn::config::verifier::VerifierConfig::builder().root_store(RootCertStore::mozilla());
        let verifier_config = builder
            .build()
            .map_err(|e| SdkError::config(e.to_string()))?;
        let verifier = handle
            .new_verifier(verifier_config)
            .map_err(|e| SdkError::protocol(e.to_string()))?;

        self.state = State::Connected { verifier, handle };

        info!("connected to prover");

        Ok(())
    }

    /// Performs the commitment handshake with the prover.
    ///
    /// Returns `Some(server_name)` if proxy sockets are needed
    /// (call `set_proxy_sockets()` before `verify()`), or `None` for MPC mode.
    pub async fn setup(&mut self) -> Result<Option<String>> {
        let State::Connected { verifier, handle } = self.state.take() else {
            return Err(SdkError::invalid_state(
                "verifier is not in connected state",
            ));
        };

        let verifier = verifier
            .commit()
            .await
            .map_err(|e| SdkError::protocol(e.to_string()))?;

        match verifier.request().clone() {
            TlsCommitRequest::Mpc(mpc_tls_config) => {
                let reject = if mpc_tls_config.max_sent_data() > self.config.max_sent_data {
                    Some("max_sent_data is too large")
                } else if mpc_tls_config.max_recv_data() > self.config.max_recv_data {
                    Some("max_recv_data is too large")
                } else if mpc_tls_config.max_sent_records() > self.config.max_sent_records {
                    Some("max_sent_records is too large")
                } else if mpc_tls_config.max_recv_records_online()
                    > self.config.max_recv_records_online
                {
                    Some("max_recv_records_online is too large")
                } else {
                    None
                };

                if reject.is_some() {
                    verifier
                        .reject(reject)
                        .await
                        .map_err(|e| SdkError::protocol(e.to_string()))?;
                    return Err(SdkError::protocol("protocol configuration rejected"));
                }

                let verifier = verifier
                    .accept(mpc_tls_config)
                    .await
                    .map_err(|e| SdkError::protocol(e.to_string()))?;

                self.state = State::AcceptedMpc { verifier, handle };

                Ok(None)
            }
            TlsCommitRequest::Proxy(proxy_tls_config) => {
                let server_name = proxy_tls_config.server_name().to_string();

                let verifier = verifier
                    .accept(proxy_tls_config)
                    .await
                    .map_err(|e| SdkError::protocol(e.to_string()))?;

                self.state = State::AcceptedProxy {
                    verifier,
                    handle,
                    server_socket: None,
                };

                Ok(Some(server_name))
            }
            _ => {
                verifier
                    .reject(Some("unsupported protocol configuration"))
                    .await
                    .map_err(|e| SdkError::protocol(e.to_string()))?;
                Err(SdkError::protocol("unsupported protocol configuration"))
            }
        }
    }

    /// Provides the server socket for proxy mode.
    ///
    /// Must be called between [`setup`](Self::setup) and [`run`](Self::run)
    /// when `setup` returned a server name. Has no effect in MPC mode and
    /// will return an error if the verifier is not in the accepted proxy
    /// state.
    pub fn set_server_socket(&mut self, server_socket: impl Io) -> Result<()> {
        let State::AcceptedProxy {
            server_socket: slot,
            ..
        } = &mut self.state
        else {
            return Err(SdkError::invalid_state(
                "verifier is not in accepted proxy state",
            ));
        };

        *slot = Some(Box::new(server_socket));
        Ok(())
    }

    /// Runs the verifier until the TLS connection is closed.
    ///
    /// In proxy mode, [`set_server_socket`](Self::set_server_socket) must be
    /// called first.
    pub async fn run(&mut self) -> Result<()> {
        match self.state.take() {
            State::AcceptedMpc { verifier, handle } => {
                let verifier = verifier
                    .run()
                    .await
                    .map_err(|e| SdkError::protocol(e.to_string()))?;

                self.state = State::Committed { verifier, handle };
                Ok(())
            }
            State::AcceptedProxy {
                verifier,
                handle,
                server_socket: Some(server_socket),
            } => {
                let verifier = verifier
                    .run(server_socket)
                    .await
                    .map_err(|e| SdkError::protocol(e.to_string()))?;

                self.state = State::Committed { verifier, handle };
                Ok(())
            }
            State::AcceptedProxy {
                server_socket: None,
                ..
            } => Err(SdkError::invalid_state(
                "server socket not set; call set_server_socket() first",
            )),
            _ => Err(SdkError::invalid_state(
                "verifier is not in accepted state",
            )),
        }
    }

    /// Verifies the connection and finalizes the protocol.
    pub async fn verify(&mut self) -> Result<VerifierOutput> {
        let State::Committed { verifier, handle } = self.state.take() else {
            return Err(SdkError::invalid_state("verifier is not in accepted state"));
        };

        let sent = verifier
            .tls_transcript()
            .sent()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
            .map(|record| record.ciphertext.len())
            .sum::<usize>();

        let received = verifier
            .tls_transcript()
            .recv()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
            .map(|record| record.ciphertext.len())
            .sum::<usize>();

        let connection_info = ConnectionInfo {
            time: verifier.tls_transcript().time(),
            version: *verifier.tls_transcript().version(),
            transcript_length: TranscriptLength {
                sent: sent as u32,
                received: received as u32,
            },
        };

        let (output, verifier) = verifier
            .verify()
            .await
            .map_err(|e| SdkError::protocol(e.to_string()))?
            .accept()
            .await
            .map_err(|e| SdkError::protocol(e.to_string()))?;
        verifier
            .close()
            .await
            .map_err(|e| SdkError::protocol(e.to_string()))?;

        handle.close();

        self.state = State::Complete;

        info!("verification complete");

        Ok(VerifierOutput {
            server_name: output.server_name.map(|name| {
                let ServerName::Dns(name) = name;
                name.to_string()
            }),
            connection_info: crate::types::ConnectionInfo::from(connection_info),
            transcript: output.transcript.map(crate::types::PartialTranscript::from),
        })
    }

    /// Returns true if the verifier has completed the protocol.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}
