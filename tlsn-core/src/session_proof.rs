use serde::{Deserialize, Serialize};

use crate::{handshake_data::HandshakeData, session_header::SessionHeaderMsg};

#[derive(Serialize, Deserialize)]
pub struct SessionProof {
    header: SessionHeaderMsg,
    handshake_data: HandshakeData,
}

impl SessionProof {
    pub fn new(header: SessionHeaderMsg, handshake_data: HandshakeData) -> Self {
        Self {
            header,
            handshake_data,
        }
    }

    pub fn header(&self) -> &SessionHeaderMsg {
        &self.header
    }

    pub fn handshake_data(&self) -> &HandshakeData {
        &self.handshake_data
    }
}
