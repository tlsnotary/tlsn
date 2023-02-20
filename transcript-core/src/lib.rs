//! This crate contains types associated with the notarized transcript

pub mod commitment;
pub mod document;
pub mod error;
pub mod merkle;
pub mod pubkey;
pub mod signed;
pub mod tls_handshake;

pub type HashCommitment = [u8; 32];

/// A PRG seeds from which to generate garbled circuit active labels, see
/// [crate::commitment::CommitmentType::labels_blake3]
pub type LabelSeed = [u8; 32];
