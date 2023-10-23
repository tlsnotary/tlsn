//! TLS session types.

mod data;
mod handshake;
mod header;

use serde::{Deserialize, Serialize};

pub use data::{NotarizationSessionData, SessionData};
pub use handshake::{HandshakeSummary, HandshakeVerifyError};
pub use header::{SessionHeader, SessionHeaderVerifyError};

use crate::{
    proof::{SessionInfo, SessionProof},
    signature::Signature,
};

/// A validated notarized session stored by the Prover
#[derive(Serialize, Deserialize)]
pub struct NotarizedSession {
    header: SessionHeader,
    signature: Option<Signature>,
    data: NotarizationSessionData,
}

opaque_debug::implement!(NotarizedSession);

impl NotarizedSession {
    /// Create a new notarized session.
    pub fn new(
        header: SessionHeader,
        signature: Option<Signature>,
        data: NotarizationSessionData,
    ) -> Self {
        Self {
            header,
            signature,
            data,
        }
    }

    /// Returns a proof of the TLS session
    pub fn session_proof(&self) -> SessionProof {
        let server_info = SessionInfo {
            server_name: self.data.session_data().session_info().server_name.clone(),
            handshake_data_decommitment: self
                .data
                .session_data()
                .session_info()
                .handshake_data_decommitment()
                .clone(),
        };

        SessionProof {
            header: self.header.clone(),
            signature: self.signature.clone(),
            server_info,
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

    /// Returns the [NotarizationSessionData]
    pub fn data(&self) -> &NotarizationSessionData {
        &self.data
    }
}
