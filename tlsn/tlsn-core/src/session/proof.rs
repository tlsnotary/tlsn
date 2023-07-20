use serde::{Deserialize, Serialize};

use mpz_core::commit::Decommitment;
use tls_core::handshake::HandshakeData;

use super::SessionHeader;
use crate::signature::Signature;

/// A proof for a TLSNotary session
#[derive(Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct SessionProof {
    pub header: SessionHeader,
    pub signature: Option<Signature>,
    pub handshake_data_decommitment: Decommitment<HandshakeData>,
}

impl SessionProof {
    /// Create a new instance of SessionProof
    pub fn new(
        header: SessionHeader,
        signature: Option<Signature>,
        handshake_data_decommitment: Decommitment<HandshakeData>,
    ) -> Self {
        Self {
            header,
            signature,
            handshake_data_decommitment,
        }
    }

    /// Returns the [SessionHeader]
    pub fn header(&self) -> &SessionHeader {
        &self.header
    }

    /// Returns the decommitment to [HandshakeData]
    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }
}
