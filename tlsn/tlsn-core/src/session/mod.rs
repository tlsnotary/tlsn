//! TLS session types.

mod data;
mod handshake;
mod header;
mod proof;

use serde::{Deserialize, Serialize};

pub use data::{SessionData, SessionDataBuilder};
pub use handshake::{HandshakeSummary, HandshakeVerifyError};
pub use header::{SessionHeader, SessionHeaderVerifyError};
pub use proof::SessionProof;

use crate::signature::Signature;

/// A validated notarized session stored by the Prover
#[derive(Serialize, Deserialize)]
pub struct NotarizedSession {
    header: SessionHeader,
    signature: Option<Signature>,
    data: SessionData,
}

impl NotarizedSession {
    /// Create a new instance of [NotarizedSession]
    pub fn new(header: SessionHeader, signature: Option<Signature>, data: SessionData) -> Self {
        Self {
            header,
            signature,
            data,
        }
    }

    /// Generates a new [SessionProof] from this [NotarizedSession]
    pub fn session_proof(&self) -> SessionProof {
        SessionProof::new(
            self.header().clone(),
            self.signature().clone(),
            self.data().handshake_data_decommitment().clone(),
        )
    }

    /// Returns the [SessionHeader]
    pub fn header(&self) -> &SessionHeader {
        &self.header
    }

    /// Returns the signature for the session header, if the notary signed it
    pub fn signature(&self) -> &Option<Signature> {
        &self.signature
    }

    /// Returns the [SessionData]
    pub fn data(&self) -> &SessionData {
        &self.data
    }
}
