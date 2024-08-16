//! Protocol message types.

use serde::{Deserialize, Serialize};

#[cfg(feature = "mpz")]
use utils::range::RangeSet;

#[cfg(feature = "mpz")]
use crate::{ proof::SessionInfo, SessionHeader};

use crate::signature::Signature;

/// Top-level enum for all messages
#[derive(Debug, Serialize, Deserialize)]
#[cfg(feature = "mpz")]
pub enum TlsnMessage {
    /// A session header signed by a notary.
    SignedSessionHeader(SignedSessionHeader),
    /// A signature on application data
    SignedSession(SignedSession),
    /// A session header.
    SessionHeader(SessionHeader),
    /// Information about the TLS session
    SessionInfo(SessionInfo),
    /// Information about the values the prover wants to prove
    ProvingInfo(ProvingInfo),
}

/// Top-level enum for all messages
#[derive(Debug, Serialize, Deserialize)]
#[cfg(feature = "tee")]
pub enum TlsnMessage {
    /// A signature on application data
    SignedSession(SignedSession),
}

/// A signed session header.
#[derive(Debug, Serialize, Deserialize)]
#[cfg(feature = "mpz")]
pub struct SignedSessionHeader {
    /// The session header
    pub header: SessionHeader,
    /// The notary's signature
    pub signature: Signature,
}

/// A signed session.
#[derive(Serialize, Deserialize, Clone)]
#[cfg(feature = "tee")]
pub struct SignedSession {
    /// The TLS application data
    pub application_data: String,
    /// The signature on application data
    pub signature: Signature,
}

#[cfg(feature = "tee")]
opaque_debug::implement!(SignedSession);

#[cfg(feature = "tee")]
impl SignedSession {
    /// Create a new notarized session.
    pub fn new(application_data: String, signature: Signature) -> Self {
        Self {
            application_data,
            signature,
        }
    }
}

/// Information about the values the prover wants to prove
#[derive(Debug, Serialize, Deserialize, Default)]
#[cfg(feature = "mpz")]
pub struct ProvingInfo {
    /// The ids for the sent transcript
    pub sent_ids: RangeSet<usize>,
    /// The ids for the received transcript
    pub recv_ids: RangeSet<usize>,
    /// Purported cleartext values
    pub cleartext: Vec<u8>,
}
