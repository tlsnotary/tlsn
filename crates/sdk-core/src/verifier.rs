//! SDK Verifier implementation.

use enum_try_as_inner::EnumTryAsInner;
use tlsn::{
    config::tls_commit::TlsCommitProtocolConfig,
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

#[derive(EnumTryAsInner)]
#[derive_err(Debug)]
#[allow(clippy::large_enum_variant, unused_assignments)]
enum State {
    Initialized,
    Connected {
        verifier: Verifier<state::Initialized>,
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

        let verifier_config = tlsn::config::verifier::VerifierConfig::builder()
            .root_store(RootCertStore::mozilla())
            .build()
            .map_err(|e| SdkError::config(e.to_string()))?;
        let verifier = handle
            .new_verifier(verifier_config)
            .map_err(|e| SdkError::protocol(e.to_string()))?;

        self.state = State::Connected { verifier, handle };

        info!("connected to prover");

        Ok(())
    }

    /// Verifies the connection and finalizes the protocol.
    pub async fn verify(&mut self) -> Result<VerifierOutput> {
        let State::Connected { verifier, handle } = self.state.take() else {
            return Err(SdkError::invalid_state(
                "verifier is not in connected state",
            ));
        };

        let max_sent_data = self.config.max_sent_data;
        let max_recv_data = self.config.max_recv_data;
        let max_sent_records = self.config.max_sent_records;
        let max_recv_records_online = self.config.max_recv_records_online;

        let verifier = verifier
            .commit()
            .await
            .map_err(|e| SdkError::protocol(e.to_string()))?;
        let request = verifier.request();

        let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = request.protocol() else {
            return Err(SdkError::protocol("only MPC protocol is supported"));
        };

        let reject = if mpc_tls_config.max_sent_data() > max_sent_data {
            Some("max_sent_data is too large")
        } else if mpc_tls_config.max_recv_data() > max_recv_data {
            Some("max_recv_data is too large")
        } else if mpc_tls_config.max_sent_records() > max_sent_records {
            Some("max_sent_records is too large")
        } else if mpc_tls_config.max_recv_records_online() > max_recv_records_online {
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
            .accept()
            .await
            .map_err(|e| SdkError::protocol(e.to_string()))?
            .run()
            .await
            .map_err(|e| SdkError::protocol(e.to_string()))?;

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
