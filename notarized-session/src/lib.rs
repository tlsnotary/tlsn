pub mod commitment;
pub mod error;
pub mod handshake_data;
pub mod handshake_summary;
pub mod session_data;
pub mod session_header;
pub mod transcript;

use session_data::SessionData;
use session_header::SessionHeader;

pub type HashCommitment = [u8; 32];

/// A PRG seeds from which to generate garbled circuit active labels, see
/// [crate::commitment::CommitmentType::labels_blake3]
pub type LabelSeed = [u8; 32];

pub struct NotarizedSession {
    version: u8,
    session_header: SessionHeader,
    session_data: SessionData,
}

impl NotarizedSession {
    pub fn new(version: u8, session_header: SessionHeader, session_data: SessionData) -> Self {
        Self {
            version,
            session_header,
            session_data,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn session_header(&self) -> &SessionHeader {
        &self.session_header
    }

    pub fn session_data(&self) -> &SessionData {
        &self.session_data
    }
}
