pub mod commitment;
pub mod error;
pub mod handshake_data;
pub mod handshake_summary;
pub mod session_data;
pub mod session_header;
pub mod transcript;

pub use session_data::SessionData;
pub use session_header::SessionHeader;

pub type HashCommitment = [u8; 32];

/// A PRG seeds from which to generate garbled circuit active labels, see
/// [crate::commitment::CommitmentType::labels_blake3]
pub type LabelSeed = [u8; 32];

pub struct NotarizedSession {
    version: u8,
    header: SessionHeader,
    data: SessionData,
}

impl NotarizedSession {
    pub fn new(version: u8, header: SessionHeader, data: SessionData) -> Self {
        Self {
            version,
            header,
            data,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn header(&self) -> &SessionHeader {
        &self.header
    }

    pub fn data(&self) -> &SessionData {
        &self.data
    }
}
