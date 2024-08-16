//! TLS session types.

mod data;
mod handshake;
mod header;

#[cfg(feature = "mpz")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "mpz")]
pub use data::SessionData;
#[cfg(feature = "mpz")]
pub use handshake::{HandshakeSummary, HandshakeVerifyError};
#[cfg(feature = "mpz")]
pub use header::{SessionHeader, SessionHeaderVerifyError};

#[cfg(feature = "mpz")]
use crate::{
    proof::{SessionInfo, SessionProof},
    signature::Signature,
};

/// A validated notarized session stored by the Prover
#[derive(Serialize, Deserialize)]
#[cfg(feature = "mpz")]
pub struct NotarizedSession {
    header: SessionHeader,
    signature: Option<Signature>,
    data: SessionData,
}

#[cfg(feature = "mpz")]
opaque_debug::implement!(NotarizedSession);

#[cfg(feature = "mpz")]
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
        let session_info = SessionInfo {
            server_name: self.data.session_info().server_name.clone(),
            handshake_decommitment: self.data.session_info().handshake_decommitment.clone(),
        };

        SessionProof {
            header: self.header.clone(),
            signature: self.signature.clone(),
            session_info,
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
