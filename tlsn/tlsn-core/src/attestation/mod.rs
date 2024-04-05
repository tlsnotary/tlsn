//! Attestation types.

mod builder;
mod proof;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    conn::{
        CertificateSecrets, ConnectionInfo, HandshakeData, ServerIdentity, ServerIdentityProof,
    },
    encoding::{EncodingCommitment, EncodingTree},
    hash::{Hash, HashAlgorithm, PlaintextHash, PlaintextHashProof},
    merkle::MerkleTree,
    serialize::CanonicalSerialize,
    substring::{SubstringProof, SubstringProofConfig, SubstringProofConfigBuilder},
    transcript::SubsequenceIdx,
    Signature, Transcript,
};

pub use builder::AttestationBodyBuilder;
pub use proof::BodyProof;
pub use validation::InvalidAttestationBody;

/// The current version of attestations.
pub static ATTESTATION_VERSION: AttestationVersion = AttestationVersion(0);

pub(crate) const ATTESTATION_VERSION_LEN: usize = 4;
pub(crate) const ATTESTATION_ID_LEN: usize = 16;

/// An attestation error.
#[derive(Debug)]
pub struct AttestationError;

/// An identifier for an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationId(pub [u8; ATTESTATION_ID_LEN]);

impl From<[u8; ATTESTATION_ID_LEN]> for AttestationId {
    fn from(id: [u8; ATTESTATION_ID_LEN]) -> Self {
        Self(id)
    }
}

/// The version of an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationVersion(u32);

impl AttestationVersion {
    pub(crate) fn to_le_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

/// A secret hidden from the Notary.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Secret {
    /// The certificate chain and signature.
    #[serde(rename = "cert")]
    Certificate(CertificateSecrets),
    /// The server's identity.
    #[serde(rename = "server_identity")]
    ServerIdentity(ServerIdentity),
    /// A merkle tree of transcript encodings.
    #[serde(rename = "encoding")]
    EncodingTree(EncodingTree),
    /// A hash of a range of plaintext in the transcript.
    #[serde(rename = "hash")]
    PlaintextHash {
        /// The subsequence of the transcript.
        seq: SubsequenceIdx,
        /// The nonce which was hashed with the plaintext.
        nonce: [u8; 16],
        /// The id of the plaintext hash public field.
        commitment: FieldId,
    },
}

opaque_debug::implement!(Secret);

/// A public attestation field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// TLS connection information.
    ConnectionInfo(ConnectionInfo),
    /// TLS handshake data.
    HandshakeData(HandshakeData),
    /// Commitment to the server's certificate and signature.
    CertificateCommitment(Hash),
    /// Commitment to the certificate chain.
    CertificateChainCommitment(Hash),
    /// Commitment to the encodings of the transcript plaintext.
    EncodingCommitment(EncodingCommitment),
    /// A hash of a range of plaintext in the transcript.
    PlaintextHash(PlaintextHash),
    /// Arbitrary extra data bound to the attestation.
    ExtraData(Vec<u8>),
}

impl Field {
    /// Returns the kind of the field.
    pub fn kind(&self) -> FieldKind {
        match self {
            Field::ConnectionInfo(_) => FieldKind::ConnectionInfo,
            Field::HandshakeData(_) => FieldKind::HandshakeData,
            Field::CertificateCommitment(_) => FieldKind::CertificateCommitment,
            Field::CertificateChainCommitment(_) => FieldKind::CertificateChainCommitment,
            Field::EncodingCommitment(_) => FieldKind::EncodingCommitment,
            Field::PlaintextHash(_) => FieldKind::PlaintextHash,
            Field::ExtraData(_) => FieldKind::ExtraData,
        }
    }
}

/// The kind of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FieldKind {
    /// TLS connection information.
    ConnectionInfo = 0x00,
    /// TLS handshake data.
    HandshakeData = 0x01,
    /// Commitment to the server's certificate and signature.
    CertificateCommitment = 0x02,
    /// Commitment to the certificate chain.
    CertificateChainCommitment = 0x03,
    /// Commitment to the encodings of the transcript plaintext.
    EncodingCommitment = 0x04,
    /// A hash of a range of plaintext in the transcript.
    PlaintextHash = 0x05,
    /// Arbitrary extra data bound to the attestation.
    ExtraData = 0xff,
}

/// An identifier for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FieldId(pub u32);

/// An attestation header.
///
/// A header is the data structure which is signed by the Notary. It contains
/// a unique identifier, the protocol version, and a Merkle root of the
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

impl AttestationHeader {
    /// Serializes the header to its canonical form.
    pub fn serialize(&self) -> Vec<u8> {
        CanonicalSerialize::serialize(self)
    }
}

/// The body of an attestation.
///
/// An attestation contains a set of fields which are cryptographically signed by
/// the Notary via an [`AttestationHeader`]. These fields include data which can be
/// used to verify aspects of a TLS connection, such as the server's identity, and facts
/// about the transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "validation::AttestationBodyUnchecked")]
pub struct AttestationBody {
    /// The fields of the attestation.
    fields: HashMap<FieldId, Field>,
}

impl AttestationBody {
    pub(crate) fn new(fields: HashMap<FieldId, Field>) -> Result<Self, InvalidAttestationBody> {
        Self::validate(Self { fields })
    }

    /// Computes the Merkle root of the attestation fields.
    pub fn root(&self, alg: HashAlgorithm) -> Hash {
        let mut tree = MerkleTree::new(alg);
        let mut fields = self.fields.iter().collect::<Vec<_>>();
        fields.sort_by_key(|(id, _)| *id);

        for (_, field) in fields {
            tree.insert(field)
        }

        tree.root()
    }

    /// Returns the field with the given id.
    pub fn get(&self, id: &FieldId) -> Option<&Field> {
        self.fields.get(id)
    }

    /// Returns an iterator over the fields.
    pub fn iter(&self) -> impl Iterator<Item = (&FieldId, &Field)> {
        self.fields.iter()
    }

    pub(crate) fn get_info(&self) -> Option<&ConnectionInfo> {
        self.fields.iter().find_map(|(_, field)| match field {
            Field::ConnectionInfo(info) => Some(info),
            _ => None,
        })
    }

    pub(crate) fn get_encoding_commitment(&self) -> Option<&EncodingCommitment> {
        self.fields.iter().find_map(|(_, field)| match field {
            Field::EncodingCommitment(commitment) => Some(commitment),
            _ => None,
        })
    }
}

/// An attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// The signature of the attestation.
    pub sig: Signature,
    /// The attestation header.
    pub header: AttestationHeader,
    /// The attestation body.
    pub body: AttestationBody,
}

impl Attestation {
    /// Creates a new attestation builder.
    pub fn builder() -> AttestationBodyBuilder {
        AttestationBodyBuilder::default()
    }
}

/// The full data of an attestation, including private fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationFull {
    /// The signature of the attestation.
    pub sig: Signature,
    /// The attestation header.
    pub header: AttestationHeader,
    /// The attestation body.
    pub body: AttestationBody,
    /// Transcript of data communicated between the Prover and the Server.
    pub transcript: Transcript,
    /// Secret data of the attestation.
    pub secrets: Vec<Secret>,
}

impl AttestationFull {
    /// Returns the attestation.
    pub fn to_attestation(&self) -> Attestation {
        Attestation {
            sig: self.sig.clone(),
            header: self.header.clone(),
            body: self.body.clone(),
        }
    }

    /// Returns a server identity proof.
    pub fn identity_proof(&self) -> Result<ServerIdentityProof, AttestationError> {
        let cert_secrets = self
            .secrets
            .iter()
            .find_map(|secret| match secret {
                Secret::Certificate(cert_secrets) => Some(cert_secrets),
                _ => None,
            })
            .unwrap();

        let identity = self
            .secrets
            .iter()
            .find_map(|secret| match secret {
                Secret::ServerIdentity(identity) => Some(identity.clone()),
                _ => None,
            })
            .unwrap();

        Ok(ServerIdentityProof {
            cert_secrets: cert_secrets.clone(),
            identity,
        })
    }

    /// Returns a substring proof config builder.
    pub fn substring_proof_config_builder(&self) -> SubstringProofConfigBuilder {
        SubstringProofConfigBuilder::new(&self.transcript)
    }

    /// Returns a substring proof.
    pub fn substring_proof(
        &self,
        config: &SubstringProofConfig,
    ) -> Result<SubstringProof, AttestationError> {
        let mut hash_openings = Vec::new();
        let mut encoding_idx = Vec::new();

        for idx in config.iter() {
            if let Some((nonce, commitment)) = self.secrets.iter().find_map(|secret| match secret {
                Secret::PlaintextHash {
                    seq,
                    nonce,
                    commitment,
                } if seq == idx => Some((*nonce, commitment)),
                _ => None,
            }) {
                let (_, data) = self
                    .transcript
                    .get_subsequence(idx)
                    .expect("subsequence is in transcript")
                    .into_parts();
                hash_openings.push(PlaintextHashProof {
                    data,
                    nonce,
                    commitment: *commitment,
                });
                continue;
            }

            encoding_idx.push(idx);
        }

        let encoding_proof = if !encoding_idx.is_empty() {
            let encoding_tree = self.get_encoding_tree().unwrap();
            Some(
                encoding_tree
                    .proof(&self.transcript, encoding_idx.into_iter())
                    .unwrap(),
            )
        } else {
            None
        };

        Ok(SubstringProof {
            encoding: encoding_proof,
            hash_openings,
        })
    }

    fn get_encoding_tree(&self) -> Option<&EncodingTree> {
        self.secrets.iter().find_map(|secret| match secret {
            Secret::EncodingTree(tree) => Some(tree),
            _ => None,
        })
    }
}

mod validation {
    use super::*;

    /// An error indicating that an attestation body is invalid.
    #[derive(Debug, thiserror::Error)]
    #[error("invalid attestation body: {0}")]
    pub struct InvalidAttestationBody(String);

    impl AttestationBody {
        pub(crate) fn validate(self) -> Result<Self, InvalidAttestationBody> {
            let mut counts = HashMap::<FieldKind, usize>::new();
            for field in self.fields.values() {
                let kind = field.kind();
                let count = counts.entry(kind).or_default();

                // Only allow one of each of these fields.
                if matches!(
                    kind,
                    FieldKind::ConnectionInfo
                        | FieldKind::HandshakeData
                        | FieldKind::CertificateCommitment
                        | FieldKind::EncodingCommitment
                ) && *count > 0
                {
                    return Err(InvalidAttestationBody(format!(
                        "only 1 {:?} field can be present",
                        kind
                    )));
                }

                *count += 1;
            }

            Ok(self)
        }
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct AttestationBodyUnchecked {
        fields: HashMap<FieldId, Field>,
    }

    impl TryFrom<AttestationBodyUnchecked> for AttestationBody {
        type Error = InvalidAttestationBody;

        fn try_from(body: AttestationBodyUnchecked) -> Result<Self, Self::Error> {
            AttestationBody::new(body.fields)
        }
    }
}
