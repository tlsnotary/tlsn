use mpc_core::commit::Decommitment;
use serde::{Deserialize, Serialize};

use crate::{handshake_data::HandshakeData, session::session_header::SessionHeaderMsg};

#[derive(Serialize, Deserialize)]
pub struct SessionProof {
    header: SessionHeaderMsg,
    handshake_data_decommitment: Decommitment<HandshakeData>,
}

impl SessionProof {
    pub fn new(
        header: SessionHeaderMsg,
        handshake_data_decommitment: Decommitment<HandshakeData>,
    ) -> Self {
        Self {
            header,
            handshake_data_decommitment,
        }
    }

    pub fn header(&self) -> &SessionHeaderMsg {
        &self.header
    }

    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }
}
