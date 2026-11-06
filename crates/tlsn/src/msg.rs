use std::fmt;

use semver::Version;
use serde::{Deserialize, Serialize};

use tlsn_core::{
    config::{prove::ProveRequest, tls_commit::TlsCommitConfig},
    connection::{HandshakeData, ServerName},
    transcript::PartialTranscript,
};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TlsCommitRequestMsg {
    pub(crate) config: TlsCommitConfig,
    pub(crate) version: Version,
}

/// One-way message telling the verifier that the prover is done with the
/// proxy connection.
///
/// Carries how many TLS bytes the prover consumed in each direction.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProxyFinished {
    /// Bytes the prover sent to the server.
    pub(crate) tls_sent: u64,
    /// Bytes the prover received from the server.
    pub(crate) tls_recv: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProveRequestMsg {
    pub(crate) request: ProveRequest,
    pub(crate) handshake: Option<(ServerName, HandshakeData)>,
    pub(crate) transcript: Option<PartialTranscript>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Response {
    pub(crate) result: Result<(), RejectionReason>,
}

impl Response {
    pub(crate) fn ok() -> Self {
        Self { result: Ok(()) }
    }

    pub(crate) fn err(msg: Option<impl Into<String>>) -> Self {
        Self {
            result: Err(RejectionReason(msg.map(Into::into))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RejectionReason(Option<String>);

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(msg) = &self.0 {
            write!(f, "{msg}")
        } else {
            write!(f, "no reason provided")
        }
    }
}

impl std::error::Error for RejectionReason {}
