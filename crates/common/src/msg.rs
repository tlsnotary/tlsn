//! Message types.

use serde::{Deserialize, Serialize};

use tlsn_core::connection::{ServerCertData, ServerName};

/// Message sent from Prover to Verifier to prove the server identity.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerIdentityProof {
    /// Server name.
    pub name: ServerName,
    /// Server identity data.
    pub data: ServerCertData,
}
