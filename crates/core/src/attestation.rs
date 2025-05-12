//! Attestation types.
//!
//! An attestation is a cryptographically signed document issued by a Notary who
//! witnessed a TLS connection. It contains various fields which can be used to
//! verify statements about the connection and the associated application data.
//!
//! Attestations are comprised of two parts: a [`Header`] and a [`Body`].
//!
//! The header is the data structure which is signed by a Notary. It
//! contains a unique identifier, the protocol version, and a Merkle root
//! of the body fields.
//!
//! The body contains the fields of the attestation. These fields include data
//! which can be used to verify aspects of a TLS connection, such as the
//! server's identity, and facts about the transcript.
//!
//! # Extensions
//!
//! An attestation may be extended using [`Extension`] fields included in the
//! body. Extensions (currently) have no canonical semantics, but may be used to
//! implement application specific functionality.
//!
//! A Prover may [append
//! extensions](crate::request::RequestConfigBuilder::extension)
//! to their attestation request, provided that the Notary supports them
//! (disallowed by default). A Notary may also be configured to
//! [validate](crate::attestation::AttestationConfigBuilder::extension_validator)
//! any extensions requested by a Prover using custom application logic.
//! Additionally, they  may
//! [include](crate::attestation::AttestationBuilder::extension)
//! their own extensions.

mod builder;
mod config;
mod extension;
mod proof;

use std::fmt;

use rand::distr::{Distribution, StandardUniform};
use serde::{Deserialize, Serialize};

use crate::{
    connection::{ConnectionInfo, ServerCertCommitment, ServerEphemKey},
    hash::{impl_domain_separator, Hash, HashAlgorithm, HashAlgorithmExt, TypedHash},
    index::Index,
    merkle::MerkleTree,
    presentation::PresentationBuilder,
    serialize::CanonicalSerialize,
    signing::{Signature, VerifyingKey},
    transcript::{encoding::EncodingCommitment, hash::PlaintextHash},
    CryptoProvider,
};

pub use builder::{AttestationBuilder, AttestationBuilderError};
pub use config::{AttestationConfig, AttestationConfigBuilder, AttestationConfigError};
pub use extension::{Extension, InvalidExtension};
pub use proof::{AttestationError, AttestationProof};

/// Current version of attestations.
pub const VERSION: Version = Version(0);

/// Unique identifier for an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Uid(pub [u8; 16]);

impl From<[u8; 16]> for Uid {
    fn from(id: [u8; 16]) -> Self {
        Self(id)
    }
}

impl Distribution<Uid> for StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Uid {
        Uid(self.sample(rng))
    }
}

/// Version of an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version(u32);

impl_domain_separator!(Version);

/// Public attestation field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field<T> {
    /// Identifier of the field.
    pub id: FieldId,
    /// Field data.
    pub data: T,
}

/// Identifier for a field.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct FieldId(pub u32);

impl FieldId {
    pub(crate) fn next<T>(&mut self, data: T) -> Field<T> {
        let id = *self;
        self.0 += 1;

        Field { id, data }
    }
}

impl fmt::Display for FieldId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Kind of an attestation field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FieldKind {
    /// Connection information.
    ConnectionInfo = 0x01,
    /// Server ephemeral key.
    ServerEphemKey = 0x02,
    /// Server identity commitment.
    ServerIdentityCommitment = 0x03,
    /// Encoding commitment.
    EncodingCommitment = 0x04,
    /// Plaintext hash commitment.
    PlaintextHash = 0x05,
}

/// Attestation header.
///
/// See [module level documentation](crate::attestation) for more information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// An identifier for the attestation.
    pub id: Uid,
    /// Version of the attestation.
    pub version: Version,
    /// Merkle root of the attestation fields.
    pub root: TypedHash,
}

impl_domain_separator!(Header);

/// Attestation body.
///
/// See [module level documentation](crate::attestation) for more information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    verifying_key: Field<VerifyingKey>,
    connection_info: Field<ConnectionInfo>,
    server_ephemeral_key: Field<ServerEphemKey>,
    cert_commitment: Field<ServerCertCommitment>,
    encoding_commitment: Option<Field<EncodingCommitment>>,
    plaintext_hashes: Index<Field<PlaintextHash>>,
    extensions: Vec<Field<Extension>>,
}

impl Body {
    /// Returns an iterator over the extensions.
    pub fn extensions(&self) -> impl Iterator<Item = &Extension> {
        self.extensions.iter().map(|field| &field.data)
    }

    /// Returns the attestation verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key.data
    }

    /// Computes the Merkle root of the attestation fields.
    ///
    /// This is only used when building an attestation.
    pub(crate) fn root(&self, hasher: &dyn HashAlgorithm) -> TypedHash {
        let mut tree = MerkleTree::new(hasher.id());
        let fields = self
            .hash_fields(hasher)
            .into_iter()
            .map(|(_, hash)| hash)
            .collect::<Vec<_>>();
        tree.insert(hasher, fields);
        tree.root()
    }

    /// Returns the fields of the body hashed and sorted by id.
    ///
    /// Each field is hashed with a domain separator to mitigate type confusion
    /// attacks.
    ///
    /// # Note
    ///
    /// The order of fields is not stable across versions.
    pub(crate) fn hash_fields(&self, hasher: &dyn HashAlgorithm) -> Vec<(FieldId, Hash)> {
        // CRITICAL: ensure all fields are included! If a new field is added to the
        // struct without including it here, it will not be included in the attestation.
        let Self {
            verifying_key,
            connection_info: conn_info,
            server_ephemeral_key,
            cert_commitment,
            encoding_commitment,
            plaintext_hashes,
            extensions,
        } = self;

        let mut fields: Vec<(FieldId, Hash)> = vec![
            (verifying_key.id, hasher.hash_separated(&verifying_key.data)),
            (conn_info.id, hasher.hash_separated(&conn_info.data)),
            (
                server_ephemeral_key.id,
                hasher.hash_separated(&server_ephemeral_key.data),
            ),
            (
                cert_commitment.id,
                hasher.hash_separated(&cert_commitment.data),
            ),
        ];

        if let Some(encoding_commitment) = encoding_commitment {
            fields.push((
                encoding_commitment.id,
                hasher.hash_separated(&encoding_commitment.data),
            ));
        }

        for field in plaintext_hashes.iter() {
            fields.push((field.id, hasher.hash_separated(&field.data)));
        }

        for field in extensions.iter() {
            fields.push((field.id, hasher.hash_separated(&field.data)));
        }

        fields.sort_by_key(|(id, _)| *id);
        fields
    }

    /// Returns the connection information.
    pub(crate) fn connection_info(&self) -> &ConnectionInfo {
        &self.connection_info.data
    }

    /// Returns the server's ephemeral public key.
    pub(crate) fn server_ephemeral_key(&self) -> &ServerEphemKey {
        &self.server_ephemeral_key.data
    }

    /// Returns the commitment to a server certificate.
    pub(crate) fn cert_commitment(&self) -> &ServerCertCommitment {
        &self.cert_commitment.data
    }

    /// Returns the encoding commitment.
    pub(crate) fn encoding_commitment(&self) -> Option<&EncodingCommitment> {
        self.encoding_commitment.as_ref().map(|field| &field.data)
    }

    /// Returns the plaintext hash commitments.
    pub(crate) fn plaintext_hashes(&self) -> &Index<Field<PlaintextHash>> {
        &self.plaintext_hashes
    }
}

/// An attestation document.
///
/// See [module level documentation](crate::attestation) for more information.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Attestation {
    /// The signature of the attestation.
    pub signature: Signature,
    /// The attestation header.
    pub header: Header,
    /// The attestation body.
    pub body: Body,
}

impl Attestation {
    /// Returns an attestation builder.
    pub fn builder(config: &AttestationConfig) -> AttestationBuilder<'_> {
        AttestationBuilder::new(config)
    }

    /// Returns a presentation builder.
    pub fn presentation_builder<'a>(
        &'a self,
        provider: &'a CryptoProvider,
    ) -> PresentationBuilder<'a> {
        PresentationBuilder::new(provider, self)
    }

    /// Validates the `unchecked` attestation, returning a validated one.
    pub fn try_from_unchecked(
        unchecked: AttestationUnchecked,
        provider: &CryptoProvider,
    ) -> Result<Attestation, InvalidAttestation> {
        let verifier = provider
            .signature
            .get(&unchecked.signature.alg)
            .map_err(|_| {
                InvalidAttestation(format!(
                    "invalid signature algorithm id {:?}",
                    unchecked.signature.alg
                ))
            })?;

        verifier
            .verify(
                &unchecked.body.verifying_key.data,
                &CanonicalSerialize::serialize(&unchecked.header),
                &unchecked.signature.data,
            )
            .map_err(|_| InvalidAttestation("failed to verify the signature".into()))?;

        Ok(Self {
            body: unchecked.body,
            header: unchecked.header,
            signature: unchecked.signature,
        })
    }
}

#[doc(hidden)]
#[derive(Debug, Deserialize)]
#[serde(from = "Attestation")]
pub struct AttestationUnchecked {
    signature: Signature,
    header: Header,
    body: Body,
}

impl From<Attestation> for AttestationUnchecked {
    fn from(attestation: Attestation) -> Self {
        Self {
            body: attestation.body,
            header: attestation.header,
            signature: attestation.signature,
        }
    }
}

/// Invalid attestation error.
#[derive(Debug, thiserror::Error)]
#[error("invalid attestation: {0}")]
pub struct InvalidAttestation(String);

#[cfg(test)]
mod tests {
    use crate::{
        attestation::{Attestation, AttestationUnchecked},
        fixtures::basic_attestation_fixture,
    };

    #[test]
    fn test_validation_ok() {
        let (attestation, provider) = basic_attestation_fixture();
        let unchecked: AttestationUnchecked = attestation.into();
        let result = Attestation::try_from_unchecked(unchecked, &provider);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_err() {
        let (mut attestation, provider) = basic_attestation_fixture();

        // Corrupt the signature.
        attestation.signature.data[1] = attestation.signature.data[1].wrapping_add(1);

        let unchecked: AttestationUnchecked = attestation.into();
        let result = Attestation::try_from_unchecked(unchecked, &provider);
        assert!(result.is_err());
    }
}
