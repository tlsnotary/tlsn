use semver::Version;
use serde::{Deserialize, Serialize};

use tlsn_core::{
    config::{prove::ProveRequest, tls_commit::TlsCommitRequest},
    connection::{HandshakeData, ServerName},
    transcript::PartialTranscript,
};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TlsCommitRequestMsg {
    pub(crate) request: TlsCommitRequest,
    pub(crate) version: Version,
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

impl From<RejectionReason> for crate::prover::ProverError {
    fn from(value: RejectionReason) -> Self {
        if let Some(msg) = value.0 {
            crate::prover::ProverError::config(format!("verifier rejected with reason: {msg}"))
        } else {
            crate::prover::ProverError::config("verifier rejected without providing a reason")
        }
    }
}
