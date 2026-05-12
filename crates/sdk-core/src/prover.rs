//! SDK Prover implementation.

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use tlsn::{
    Mpc, Proxy, Session, SessionHandle,
    config::{
        prove::ProveConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    },
    connection::{DnsName, ServerName},
    prover::{Prover, TlsConnection, state},
    webpki::{CertificateDer, PrivateKeyDer},
};
use tlsn_core::{
    ProverOutput,
    transcript::{Direction, TranscriptCommitment, TranscriptSecret},
};
use tracing::{error, info};

use crate::{
    config::ProverConfig,
    error::{Result, SdkError},
    io::{HyperIo, Io},
    types::*,
};

/// SDK Prover for TLSNotary protocol.
///
/// The prover connects to both a verifier and a target server, executing the
/// MPC-TLS protocol to generate verifiable proofs of the TLS session.
pub struct SdkProver {
    config: ProverConfig,
    state: State,
}

#[allow(clippy::large_enum_variant)]
enum State {
    Initialized,
    CommitAcceptedMpc {
        prover: Prover<state::CommitAccepted<Mpc>>,
        handle: SessionHandle,
    },
    CommitAcceptedProxy {
        prover: Prover<state::CommitAccepted<Proxy>>,
        handle: SessionHandle,
    },
    Committed {
        prover: Prover<state::Committed>,
        handle: SessionHandle,
    },
    Complete,
    Error,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Initialized => write!(f, "Initialized"),
            State::CommitAcceptedMpc { .. } => write!(f, "CommitAcceptedMpc"),
            State::CommitAcceptedProxy { .. } => write!(f, "CommitAcceptedProxy"),
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

impl SdkProver {
    /// Creates a new SDK Prover with the given configuration.
    pub fn new(config: ProverConfig) -> Result<Self> {
        if config.server_name.is_empty() {
            return Err(SdkError::config("server_name cannot be empty"));
        }
        if config.mode == crate::config::ProverMode::Mpc {
            if config.max_sent_data == 0 {
                return Err(SdkError::config("max_sent_data must be > 0"));
            }
            if config.max_recv_data == 0 {
                return Err(SdkError::config("max_recv_data must be > 0"));
            }
        }

        Ok(SdkProver {
            config,
            state: State::Initialized,
        })
    }

    /// Sets up the prover with the verifier.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    ///
    /// # Arguments
    ///
    /// * `verifier_io` - A duplex IO stream connected to the verifier.
    pub async fn setup(&mut self, verifier_io: impl Io) -> Result<()> {
        let State::Initialized = self.state.take() else {
            return Err(SdkError::invalid_state(
                "prover is not in initialized state",
            ));
        };

        info!("connecting to verifier");

        let session = Session::new(verifier_io);
        let (driver, mut handle) = session.split();

        crate::spawn::spawn(async move {
            match driver.await {
                Ok(_io) => tracing::warn!("session driver completed (mux closed)"),
                Err(e) => tracing::error!("session driver error: {e}"),
            }
        });

        let prover_config = tlsn::config::prover::ProverConfig::builder().build()?;
        let prover = handle.new_prover(prover_config)?;

        if self.config.mode == crate::config::ProverMode::Proxy {
            let commit_config = ProxyTlsConfig::builder()
                .server_name(
                    DnsName::try_from(self.config.server_name.as_str())
                        .map_err(|e| SdkError::config(e.to_string()))?,
                )
                .build()?;

            let prover = prover
                .commit(commit_config)
                .await
                .map_err(|e| SdkError::protocol(e.to_string()))?;

            self.state = State::CommitAcceptedProxy { prover, handle };
        } else {
            let commit_config = {
                let mut builder = MpcTlsConfig::builder()
                    .max_sent_data(self.config.max_sent_data)
                    .max_recv_data(self.config.max_recv_data);

                if let Some(value) = self.config.max_recv_data_online {
                    builder = builder.max_recv_data_online(value);
                }

                if let Some(value) = self.config.max_sent_records {
                    builder = builder.max_sent_records(value);
                }

                if let Some(value) = self.config.max_recv_records_online {
                    builder = builder.max_recv_records_online(value);
                }

                if let Some(value) = self.config.defer_decryption_from_start {
                    builder = builder.defer_decryption_from_start(value);
                }

                builder.network(self.config.network.into()).build()?
            };

            let prover = prover
                .commit(commit_config)
                .await
                .map_err(|e| SdkError::protocol(e.to_string()))?;

            self.state = State::CommitAcceptedMpc { prover, handle };
        }

        info!("setup complete");

        Ok(())
    }

    /// Returns the protocol mode this prover is configured for.
    pub fn mode(&self) -> crate::config::ProverMode {
        self.config.mode
    }

    /// Sends an HTTP request to the server via MPC-TLS.
    ///
    /// This method is used for MPC mode only.
    ///
    /// # Arguments
    ///
    /// * `server_io` - A duplex IO stream connected to the server.
    /// * `request` - The HTTP request to send.
    pub async fn send_request_mpc(
        &mut self,
        server_io: impl Io,
        request: HttpRequest,
    ) -> Result<HttpResponse> {
        let State::CommitAcceptedMpc { prover, handle } = self.state.take() else {
            return Err(SdkError::invalid_state(
                "prover is not in commit accepted MPC state",
            ));
        };

        let tls_config = self.build_tls_config()?;

        info!("connecting to server");

        let (tls_conn, prover) = prover
            .connect(tls_config, server_io)
            .map_err(|e| SdkError::protocol(e.to_string()))?;

        info!("sending request");

        let (response, prover) = match futures::try_join!(
            async {
                let result = send_request(tls_conn, request).await;
                info!(
                    "send_request completed with result: {:?}",
                    result.as_ref().map(|_| "Ok").map_err(|e| e.to_string())
                );
                result
            },
            async {
                let result = prover.await;
                info!(
                    "prover completed with result: {:?}",
                    result.as_ref().map(|_| "Ok").map_err(|e| e.to_string())
                );
                result.map_err(|e| SdkError::protocol(e.to_string()))
            }
        ) {
            Ok(result) => {
                info!("try_join succeeded");
                result
            }
            Err(e) => {
                error!("try_join failed: {}", e);
                return Err(e);
            }
        };

        info!("response received, prover transitioning to Committed state");

        self.state = State::Committed { prover, handle };

        Ok(response)
    }

    /// Sends an HTTP request to the server via the proxy.
    ///
    /// This method is used for proxy mode only. The connection to the server
    /// is routed through the verifier.
    ///
    /// # Arguments
    ///
    /// * `request` - The HTTP request to send.
    pub async fn send_request_proxy(&mut self, request: HttpRequest) -> Result<HttpResponse> {
        let State::CommitAcceptedProxy { prover, handle } = self.state.take() else {
            return Err(SdkError::invalid_state(
                "prover is not in commit accepted proxy state",
            ));
        };

        let tls_config = self.build_tls_config()?;

        info!("connecting to proxy");

        let (tls_conn, prover) = prover
            .connect(tls_config)
            .map_err(|e| SdkError::protocol(e.to_string()))?;

        info!("sending request");

        let (response, prover) = match futures::try_join!(
            async {
                let result = send_request(tls_conn, request).await;
                info!(
                    "send_request completed with result: {:?}",
                    result.as_ref().map(|_| "Ok").map_err(|e| e.to_string())
                );
                result
            },
            async {
                let result = prover.await;
                info!(
                    "prover completed with result: {:?}",
                    result.as_ref().map(|_| "Ok").map_err(|e| e.to_string())
                );
                result.map_err(|e| SdkError::protocol(e.to_string()))
            }
        ) {
            Ok(result) => {
                info!("try_join succeeded");
                result
            }
            Err(e) => {
                error!("try_join failed: {}", e);
                return Err(e);
            }
        };

        info!("response received, prover transitioning to Committed state");

        self.state = State::Committed { prover, handle };

        Ok(response)
    }

    fn build_tls_config(&self) -> Result<TlsClientConfig> {
        let mut builder = TlsClientConfig::builder()
            .server_name(ServerName::Dns(
                self.config
                    .server_name
                    .clone()
                    .try_into()
                    .map_err(|_| SdkError::config("invalid server name"))?,
            ))
            .root_store(self.config.root_store.clone());

        if let Some(ref client_auth) = self.config.client_auth {
            let certs = client_auth
                .certs
                .iter()
                .map(|cert| {
                    // Try to parse as PEM-encoded, otherwise assume DER.
                    if let Ok(cert) = CertificateDer::from_pem_slice(cert) {
                        cert
                    } else {
                        CertificateDer(cert.clone())
                    }
                })
                .collect();
            let key = PrivateKeyDer(client_auth.key.clone());
            builder = builder.client_auth((certs, key));
        }

        Ok(builder.build()?)
    }

    /// Returns the transcript of the TLS session.
    pub fn transcript(&self) -> Result<Transcript> {
        let State::Committed { prover, .. } = &self.state else {
            return Err(SdkError::invalid_state("prover is not in committed state"));
        };

        Ok(Transcript::from(prover.transcript()))
    }

    /// Reveals data to the verifier and finalizes the protocol.
    ///
    /// Optionally accepts a [`Commit`] with ranges to hash-commit (blinded,
    /// not revealed as plaintext). The commit ranges are processed via the
    /// TLSNotary hash-commitment path (`prove_hash`).
    ///
    /// Returns a [`RevealOutput`] containing one [`CommitmentOpening`] per
    /// hash-committed range (in the same order as the input [`Commit`] —
    /// sent ranges first, then recv). When `commit` is `None`, the
    /// `commitments` vector is empty.
    pub async fn reveal(&mut self, reveal: Reveal, commit: Option<Commit>) -> Result<RevealOutput> {
        let State::Committed { mut prover, handle } = self.state.take() else {
            return Err(SdkError::invalid_state("prover is not in committed state"));
        };

        info!("reveal() called - about to send prove request to verifier");

        let mut builder = ProveConfig::builder(prover.transcript());

        for range in reveal.sent {
            builder.reveal_sent(&range)?;
        }

        for range in reveal.recv {
            builder.reveal_recv(&range)?;
        }

        if reveal.server_identity {
            builder.server_identity();
        }

        // Build transcript commit config for hash-commitment ranges.
        if let Some(commit) = commit {
            let mut commit_builder =
                tlsn_core::transcript::TranscriptCommitConfig::builder(prover.transcript());

            for (ranges, direction) in [
                (&commit.sent, tlsn_core::transcript::Direction::Sent),
                (&commit.recv, tlsn_core::transcript::Direction::Received),
            ] {
                for cr in ranges {
                    let alg: tlsn_core::hash::HashAlgId = cr.algorithm.into();
                    let kind = tlsn_core::transcript::TranscriptCommitmentKind::Hash { alg };
                    commit_builder
                        .commit_with_kind(cr.range(), direction, kind)
                        .map_err(|e| SdkError::config(e.to_string()))?;
                }
            }

            builder.transcript_commit(
                commit_builder
                    .build()
                    .map_err(|e| SdkError::config(e.to_string()))?,
            );
        }

        let config = builder.build()?;

        let prover_output = prover
            .prove(&config)
            .await
            .map_err(|e| SdkError::protocol(e.to_string()))?;
        prover
            .close()
            .await
            .map_err(|e| SdkError::protocol(e.to_string()))?;

        handle.close();

        info!("finalized");

        self.state = State::Complete;

        build_reveal_output(prover_output)
    }

    /// Returns true if the prover has completed the protocol.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}

fn build_reveal_output(output: ProverOutput) -> Result<RevealOutput> {
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
    } = output;

    if transcript_commitments.len() != transcript_secrets.len() {
        return Err(SdkError::protocol(format!(
            "prover output mismatch: {} commitments vs {} secrets",
            transcript_commitments.len(),
            transcript_secrets.len()
        )));
    }

    let mut sent = Vec::new();
    let mut recv = Vec::new();
    for (commitment, secret) in transcript_commitments.into_iter().zip(transcript_secrets) {
        let (commitment, secret) = match (commitment, secret) {
            (TranscriptCommitment::Hash(c), TranscriptSecret::Hash(s)) => (c, s),
            _ => {
                return Err(SdkError::protocol(
                    "prover output contained an unsupported commitment kind",
                ));
            }
        };

        if commitment.direction != secret.direction || commitment.idx != secret.idx {
            return Err(SdkError::protocol(
                "prover output mismatch: commitment/secret direction or range disagree",
            ));
        }

        let opening = HashOpening {
            hash: commitment.hash.value.as_bytes().to_vec(),
            blinder: secret.blinder.as_bytes().to_vec(),
        };

        match commitment.direction {
            Direction::Sent => sent.push(opening),
            Direction::Received => recv.push(opening),
        }
    }

    Ok(RevealOutput { sent, recv })
}

async fn send_request(conn: TlsConnection, request: HttpRequest) -> Result<HttpResponse> {
    let conn = HyperIo::new(conn);
    let request = hyper::Request::<Full<Bytes>>::try_from(request)?;

    let (mut request_sender, conn) = hyper::client::conn::http1::handshake(conn).await?;

    crate::spawn::spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!("HTTP connection error: {e}");
        }
    });

    let response = request_sender.send_request(request).await?;

    let (response, body) = response.into_parts();

    let body = body
        .collect()
        .await
        .map_err(|e| SdkError::http(e.to_string()))?;
    let body_bytes = body.to_bytes().to_vec();

    let headers = response
        .headers
        .into_iter()
        .map(|(k, v)| {
            (
                k.map(|k| k.to_string()).unwrap_or_default(),
                v.as_bytes().to_vec(),
            )
        })
        .collect();

    Ok(HttpResponse {
        status: response.status.as_u16(),
        headers,
        body: if body_bytes.is_empty() {
            None
        } else {
            Some(body_bytes)
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{NetworkSetting, ProverConfig},
        error::ErrorKind,
    };

    fn valid_config() -> ProverConfig {
        ProverConfig::builder("example.com")
            .max_sent_data(4096)
            .max_recv_data(16384)
            .network(NetworkSetting::Latency)
            .root_certs(vec![tlsn_server_fixture_certs::CA_CERT_DER.to_vec()])
            .build()
            .unwrap()
    }

    #[test]
    fn new_with_valid_config() {
        let prover = SdkProver::new(valid_config());
        assert!(prover.is_ok());
    }

    #[test]
    fn new_rejects_empty_server_name() {
        let config = ProverConfig::builder("")
            .max_sent_data(4096)
            .max_recv_data(16384)
            .root_certs(vec![tlsn_server_fixture_certs::CA_CERT_DER.to_vec()])
            .build()
            .unwrap();
        let err = SdkProver::new(config).err().expect("should fail");
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(err.to_string().contains("server_name"));
    }

    #[test]
    fn new_rejects_zero_max_sent_data() {
        let config = ProverConfig::builder("example.com")
            .max_sent_data(0)
            .max_recv_data(16384)
            .root_certs(vec![tlsn_server_fixture_certs::CA_CERT_DER.to_vec()])
            .build()
            .unwrap();
        let err = SdkProver::new(config).err().expect("should fail");
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(err.to_string().contains("max_sent_data"));
    }

    #[test]
    fn new_rejects_zero_max_recv_data() {
        let config = ProverConfig::builder("example.com")
            .max_sent_data(4096)
            .max_recv_data(0)
            .root_certs(vec![tlsn_server_fixture_certs::CA_CERT_DER.to_vec()])
            .build()
            .unwrap();
        let err = SdkProver::new(config).err().expect("should fail");
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(err.to_string().contains("max_recv_data"));
    }
}
