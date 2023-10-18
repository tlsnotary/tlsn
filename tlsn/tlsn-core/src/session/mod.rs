//! TLS session types.

mod data;
mod handshake;
mod header;

use serde::{Deserialize, Serialize};

pub use data::SessionData;
pub use handshake::{HandshakeSummary, HandshakeVerifyError};
pub use header::{SessionHeader, SessionHeaderVerifyError};

use crate::{proof::SessionProof, signature::Signature};

/// A validated notarized session stored by the Prover
#[derive(Serialize, Deserialize)]
pub struct NotarizedSession {
    header: SessionHeader,
    signature: Option<Signature>,
    data: SessionData,
}

opaque_debug::implement!(NotarizedSession);

impl NotarizedSession {
    /// Create a new notarized session.
    pub fn new(header: SessionHeader, signature: Option<Signature>, data: SessionData) -> Self {
        Self {
            header,
            signature,
            data,
        }
    }

    /// Returns a proof of the TLS session
    pub fn session_proof(&self) -> SessionProof {
        SessionProof {
            header: self.header.clone(),
            server_name: self.data.server_name().clone(),
            signature: self.signature.clone(),
            handshake_data_decommitment: self.data.handshake_data_decommitment().clone(),
        }
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
