mod data;
mod proof;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    conn::{ConnectionInfo, HandshakeData},
    encoding::{EncodingCommitment, EncodingTree},
    hash::{Hash, PlaintextHash},
    serialize::CanonicalSerialize,
    transcript::SubsequenceIdx,
};

/// The current version of attestations.
pub static ATTESTATION_VERSION: AttestationVersion = AttestationVersion(0);

const ATTESTATION_VERSION_LEN: usize = 4;
const ATTESTATION_ID_LEN: usize = 16;

#[derive(Debug)]
pub struct AttestationError;

/// An identifier for an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationId([u8; ATTESTATION_ID_LEN]);

/// The version of an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationVersion(u32);

/// A private attestation field.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PrivateField {
    /// TLS handshake data which can be used to prove the server's identity.
    #[serde(rename = "handshake")]
    HandshakeData {
        /// The handshake data.
        data: HandshakeData,
        /// The nonce which was hashed with the handshake data.
        nonce: [u8; 32],
    },
    /// A merkle tree of transcript encoding commitments.
    #[serde(rename = "encoding")]
    EncodingTree(EncodingTree),
    /// A hash of a range of plaintext in the transcript.
    #[serde(rename = "hash")]
    PlaintextHash {
        /// The subsequence of the transcript.
        seq: SubsequenceIdx,
        /// The nonce which was hashed with the plaintext.
        nonce: [u8; 32],
        /// The id of the plaintext hash public field.
        commitment: FieldId,
    },
}

/// A public attestation field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PublicField {
    /// TLS connection information.
    #[serde(rename = "info")]
    ConnectionInfo(ConnectionInfo),
    /// Commitment to the TLS handshake.
    #[serde(rename = "handshake")]
    HandshakeCommitment(Hash),
    /// Commitment to the encodings of the transcript plaintext.
    #[serde(rename = "encoding")]
    EncodingCommitment(EncodingCommitment),
    /// A hash of a range of plaintext in the transcript.
    #[serde(rename = "hash")]
    PlaintextHash(PlaintextHash),
    /// Arbitrary extra data bound to the attestation.
    #[serde(rename = "extra")]
    ExtraData(Vec<u8>),
}

impl PublicField {
    /// Returns the kind of the field.
    pub fn kind(&self) -> PublicFieldKind {
        match self {
            PublicField::ConnectionInfo(_) => PublicFieldKind::ConnectionInfo,
            PublicField::HandshakeCommitment(_) => PublicFieldKind::HandshakeCommitment,
            PublicField::EncodingCommitment(_) => PublicFieldKind::EncodingCommitment,
            PublicField::PlaintextHash(_) => PublicFieldKind::PlaintextHash,
            PublicField::ExtraData(_) => PublicFieldKind::ExtraData,
        }
    }
}

impl CanonicalSerialize for PublicField {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.kind() as u8);
        match self {
            PublicField::ConnectionInfo(info) => {
                bytes.extend(CanonicalSerialize::serialize(info));
            }
            PublicField::HandshakeCommitment(commitment) => {
                bytes.extend(CanonicalSerialize::serialize(commitment));
            }
            PublicField::EncodingCommitment(commitment) => {
                bytes.extend(CanonicalSerialize::serialize(commitment));
            }
            PublicField::PlaintextHash(hash) => {
                bytes.extend(CanonicalSerialize::serialize(hash));
            }
            PublicField::ExtraData(data) => {
                bytes.extend(data);
            }
        }
        bytes
    }
}

/// The kind of a field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PublicFieldKind {
    /// TLS connection information.
    ConnectionInfo = 0x00,
    /// Commitment to the TLS handshake.
    HandshakeCommitment = 0x01,
    /// Commitment to the encodings of the transcript plaintext.
    EncodingCommitment = 0x02,
    /// A hash of a range of plaintext in the transcript.
    PlaintextHash = 0x03,
    /// Arbitrary extra data bound to the attestation.
    ExtraData = 0xff,
}

/// An identifier for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FieldId(u32);

/// An attestation header.
///
/// A header is the data structure which is signed by the Notary. It contains
/// a unique idenitifer, the protocol version, and a Merkle root of the
/// attestation fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationHeader {
    /// An identifier for the attestation.
    pub id: AttestationId,
    /// Version of the attestation.
    pub version: AttestationVersion,
    /// Merkle root of the attestation fields.
    pub root: Hash,
}

impl CanonicalSerialize for AttestationHeader {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            ATTESTATION_ID_LEN + ATTESTATION_VERSION_LEN + self.root.algorithm().len(),
        );
        bytes.extend_from_slice(&self.id.0);
        bytes.extend_from_slice(&self.version.0.to_le_bytes());
        bytes.extend(CanonicalSerialize::serialize(&self.root));
        bytes
    }
}

/// The body of an attestation.
///
/// An attestation contains a set of fields which are cryptographically signed by
/// the Notary via an [`AttestationHeader`]. These fields include data which can be
/// used to verify aspects of a TLS connection, such as the server's identity, and facts
/// about the transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBody {
    /// The fields of the attestation.
    pub fields: HashMap<FieldId, PublicField>,
}
