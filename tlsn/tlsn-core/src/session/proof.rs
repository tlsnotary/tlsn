use serde::{Deserialize, Serialize};

use mpc_core::commit::Decommitment;
use tls_core::handshake::HandshakeData;

use super::SessionHeader;
use crate::signature::Signature;

#[derive(Serialize, Deserialize)]
pub struct SessionProof {
    pub header: SessionHeader,
    pub signature: Option<Signature>,
    pub handshake_data_decommitment: Decommitment<HandshakeData>,
}

impl SessionProof {
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

    pub fn header(&self) -> &SessionHeader {
        &self.header
    }

    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }
}
