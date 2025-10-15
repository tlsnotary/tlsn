use semver::Version;
use serde::{Deserialize, Serialize};

use crate::config::ProtocolConfig;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SetupRequest {
    pub(crate) config: ProtocolConfig,
    pub(crate) version: Version,
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
            crate::prover::ProverError::config(format!(
                "verifier rejected without providing a reason"
            ))
        }
    }
}
