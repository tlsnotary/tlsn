//! Core types of the prover and verifier plugin.

use serde::{Deserialize, Serialize};
use tlsn_core::{
    hash::HashAlgId,
    transcript::{Direction, TranscriptCommitmentKind},
};

mod prover;
mod verifier;

pub use prover::{
    Config as ProverPluginConfig, ConfigError as ProverPLuginConfigError,
    Output as ProverPluginOutput,
};
pub use verifier::{
    Config as VerifierPluginConfig, ConfigError as VerifierPluginConfigError,
    Output as VerifierPluginOutput,
};

/// A rule for disclosing HTTP data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureRule {
    http: HttpHandle,
    policy: DisclosurePolicy,
}

/// Handle for a part of an HTTP message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHandle {
    typ: MessageType,
    part: MessagePart,
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
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

/// Disclosure policy.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum DisclosurePolicy {
    /// Reveals data.
    Reveal,
    /// Creates a hiding commitment.
    Commit(Alg),
}

/// Commitment algorithm.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
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
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MessagePart {
    All,
    StartLine,
    Header(HeaderParams),
    Body(BodyParams),
}

/// Parameters for an HTTP header.
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct HeaderParams {
    pub key: String,
}

/// Parameters for a part of an HTTP body.
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BodyParams {
    JsonPath(String),
    XPath(String),
}
