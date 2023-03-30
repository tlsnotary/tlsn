use crate::{commitment::Commitment, handshake_data::HandshakeData, transcript::Transcript};

#[derive(Default)]
pub struct SessionData {
    handshake_data: HandshakeData,
    transcript: Transcript,
    commitments: Vec<Commitment>,
}

impl SessionData {
    pub fn new(
        handshake_data: HandshakeData,
        transcript: Transcript,
        commitments: Vec<Commitment>,
    ) -> Self {
        Self {
            handshake_data,
            transcript,
            commitments,
        }
    }

    pub fn handshake_data(&self) -> &HandshakeData {
        &self.handshake_data
    }

    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    pub fn commitments(&self) -> &[Commitment] {
        &self.commitments
    }
}
