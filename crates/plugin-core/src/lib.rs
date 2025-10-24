//! Core types of the prover and verifier plugin.

use tlsn_core::{
    ProverOutput,
    hash::{Blake3, HashAlgId},
    transcript::{Direction, TranscriptCommitmentKind},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::CA_CERT_DER;

pub mod prover;
pub mod verifier;

pub use prover::{Output as ProverPluginOutput, config::Config as ProverPluginConfig};
pub use verifier::{Output as VerifierPluginOutput, config::Config as VerifierPluginConfig};

/// Handle for an HTTP message.
// Currently used only by the prover but will be used by the
// verifier later when parsing with redactions is implemented.
pub struct Handle {
    typ: MessageType,
    part: MessagePart,
    params: Option<PartParams>,
    action: ActionType,
}

#[derive(PartialEq, Clone)]
pub enum MessageType {
    Request,
    Response,
}

impl From<&MessageType> for Direction {
    fn from(mt: &MessageType) -> Self {
        match mt {
            MessageType::Request => Direction::Sent,
            MessageType::Response => Direction::Received,
        }
    }
}

#[derive(PartialEq)]
pub enum ActionType {
    /// Reveal data to the verifier.
    Reveal,
    Commit(Alg),
}

/// Commitment algorithm.
#[derive(PartialEq)]
pub enum Alg {
    EncodingSha256,
    EncodingBlake3,
    EncodingKeccak256,
    Sha256,
    Blake3,
}

impl From<&Alg> for TranscriptCommitmentKind {
    fn from(alg: &Alg) -> Self {
        match alg {
            Alg::EncodingSha256 | Alg::EncodingBlake3 | Alg::EncodingKeccak256 => {
                TranscriptCommitmentKind::Encoding
            }
            Alg::Sha256 => TranscriptCommitmentKind::Hash {
                alg: HashAlgId::SHA256,
            },
            Alg::Blake3 => TranscriptCommitmentKind::Hash {
                alg: HashAlgId::BLAKE3,
            },
        }
    }
}

/// The part of an HTTP message.
#[derive(PartialEq, Clone)]
pub enum MessagePart {
    All,
    StartLine,
    Header,
    Body,
}

/// Parameters for [MessagePart].
#[derive(PartialEq, Clone)]
pub enum PartParams {
    Header(HeaderParams),
    Body(BodyParams),
}

#[derive(PartialEq, Clone)]
pub struct HeaderParams {
    pub key: String,
}

#[derive(PartialEq, Clone)]
pub enum BodyParams {
    JsonPath(String),
    XPath(String),
}
