//! TLSNotary attestation types.
//!
//! # Introduction
//!
//! This library provides core functionality for TLSNotary **attestations**.
//!
//! Once the TLS commitment protocol has been completed the Prover holds a
//! collection of commitments pertaining to the TLS connection. Most
//! importantly, the Prover is committed to the
//! [`ServerName`](tlsn_core::connection::ServerName),
//! and the [`Transcript`](tlsn_core::transcript::Transcript) of application
//! data. Subsequently, the Prover can request an [`Attestation`] from the
//! Notary who will include the commitments as well as any additional
//! information which may be useful to an attestation Verifier.
//!
//! Holding an attestation, the Prover can construct a
//! [`Presentation`](crate::presentation::Presentation) which facilitates
//! selectively disclosing various aspects of the TLS connection to a Verifier.
//! If the Verifier trusts the Notary, or more specifically the verifying key of
//! the attestation, then the Verifier can trust the authenticity of the
//! information disclosed in the presentation.
//!
//! **Be sure to check out the various submodules for more information.**
//!
//! # Structure
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
//! [validate](crate::AttestationConfigBuilder::extension_validator)
//! any extensions requested by a Prover using custom application logic.
//! Additionally, a Notary may
//! [include](crate::AttestationBuilder::extension)
//! their own extensions.
//!
//! # Committing to the transcript
//!
//! The TLS commitment protocol produces commitments to the entire transcript of
//! application data. However, we may want to disclose only a subset of the data
//! in a presentation. Prior to attestation, the Prover has the opportunity to
//! slice and dice the commitments into smaller sections which can be
//! selectively disclosed. Additionally, the Prover may want to use different
//! commitment schemes depending on the context they expect to disclose.
//!
//! The primary API for this process is the
//! [`TranscriptCommitConfigBuilder`](tlsn_core::transcript::TranscriptCommitConfigBuilder)
//! which is used to build up a configuration.
//!
//! ```no_run
//! # use tlsn_core::transcript::{TranscriptCommitConfigBuilder, Transcript, Direction};
//! # use tlsn_core::hash::HashAlgId;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let transcript: Transcript = unimplemented!();
//! let (sent_len, recv_len) = transcript.len();
//!
//! // Create a new configuration builder.
//! let mut builder = TranscriptCommitConfigBuilder::new(&transcript);
//!
//! // Specify all the transcript commitments we want to make.
//! builder
//!     // Use BLAKE3 for encoding commitments.
//!     .encoding_hash_alg(HashAlgId::BLAKE3)
//!     // Commit to all sent data.
//!     .commit_sent(&(0..sent_len))?
//!     // Commit to the first 10 bytes of sent data.
//!     .commit_sent(&(0..10))?
//!     // Skip some bytes so it can be omitted in the presentation.
//!     .commit_sent(&(20..sent_len))?
//!     // Commit to all received data.
//!     .commit_recv(&(0..recv_len))?;
//!
//! let config = builder.build()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Requesting an attestation
//!
//! The first step in the attestation protocol is for the Prover to make a
//! [`Request`](crate::request::Request), which can be configured using the
//! associated [builder](crate::request::RequestConfigBuilder). With it the
//! Prover can configure some of the details of the attestation, such as which
//! cryptographic algorithms are used (if the Notary supports them).
//!
//! The Prover may also request for extensions to be added to the attestation,
//! see [here](#extensions) for more information.
//!
//! Upon being issued an attestation, the Prover will also hold a corresponding
//! [`Secrets`] which contains all private information. This pair can be stored
//! and used later to construct a
//! [`Presentation`](crate::presentation::Presentation), [see
//! below](#constructing-a-presentation).
//!
//! # Issuing an attestation
//!
//! Upon receiving a request, the Notary can issue an [`Attestation`] which can
//! be configured using the associated
//! [builder](crate::AttestationConfigBuilder).
//!
//! The Notary's [`CryptoProvider`] must be configured with an appropriate
//! signing key for attestations. See
//! [`SignerProvider`](crate::signing::SignerProvider) for more information.
//!
//! # Constructing a presentation
//!
//! A Prover can use an [`Attestation`] and the corresponding [`Secrets`] to
//! construct a verifiable [`Presentation`](crate::presentation::Presentation).
//!
//! ```no_run
//! # use tlsn_attestation::{Attestation, CryptoProvider, Secrets, Presentation};
//! # use tlsn_core::transcript::{TranscriptCommitmentKind, Direction};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let attestation: Attestation = unimplemented!();
//! # let secrets: Secrets = unimplemented!();
//! # let crypto_provider: CryptoProvider = unimplemented!();
//! let (_sent_len, recv_len) = secrets.transcript().len();
//!
//! // First, we decide which application data we would like to disclose.
//! let mut builder = secrets.transcript_proof_builder();
//!
//! builder
//!     // Use transcript encoding commitments.
//!     .commitment_kinds(&[TranscriptCommitmentKind::Encoding])
//!     // Disclose the first 10 bytes of the sent data.
//!     .reveal(&(0..10), Direction::Sent)?
//!     // Disclose all of the received data.
//!     .reveal(&(0..recv_len), Direction::Received)?;
//!
//! let transcript_proof = builder.build()?;
//!
//! // Most cases we will also disclose the server identity.
//! let identity_proof = secrets.identity_proof();
//!
//! // Now we can construct the presentation.
//! let mut builder = attestation.presentation_builder(&crypto_provider);
//!
//! builder
//!     .identity_proof(identity_proof)
//!     .transcript_proof(transcript_proof);
//!
//! // Finally, we build the presentation. Send it to a verifier!
//! let presentation: Presentation = builder.build()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Verifying a presentation
//!
//! Verifying a presentation is as simple as checking the verifier trusts the
//! verifying key then calling
//! [`Presentation::verify`](crate::presentation::Presentation::verify).
//!
//! ```no_run
//! # use tlsn_attestation::{CryptoProvider, Presentation, PresentationOutput, signing::VerifyingKey};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let presentation: Presentation = unimplemented!();
//! # let trusted_key: VerifyingKey = unimplemented!();
//! # let crypto_provider: CryptoProvider = unimplemented!();
//! // Assert that we trust the verifying key.
//! assert_eq!(presentation.verifying_key(), &trusted_key);
//!
//! let PresentationOutput {
//!     attestation,
//!     server_name,
//!     connection_info,
//!     transcript,
//!     ..
//! } = presentation.verify(&crypto_provider)?;
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod builder;
mod config;
pub mod connection;
mod extension;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub(crate) mod hash;
pub mod presentation;
mod proof;
mod provider;
pub mod request;
mod secrets;
pub(crate) mod serialize;
pub mod signing;

use std::fmt;

use rand::distr::{Distribution, StandardUniform};
use serde::{Deserialize, Serialize};

use tlsn_core::{
    connection::{ConnectionInfo, ServerEphemKey},
    hash::{Hash, HashAlgorithm, TypedHash},
    merkle::MerkleTree,
    transcript::TranscriptCommitment,
};

use crate::{
    connection::ServerCertCommitment,
    hash::HashAlgorithmExt,
    presentation::PresentationBuilder,
    serialize::impl_domain_separator,
    signing::{Signature, VerifyingKey},
};

pub use builder::{AttestationBuilder, AttestationBuilderError};
pub use config::{AttestationConfig, AttestationConfigBuilder, AttestationConfigError};
pub use extension::{Extension, InvalidExtension};
pub use proof::{AttestationError, AttestationProof};
pub use provider::CryptoProvider;
pub use secrets::Secrets;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    verifying_key: Field<VerifyingKey>,
    connection_info: Field<ConnectionInfo>,
    server_ephemeral_key: Field<ServerEphemKey>,
    cert_commitment: Field<ServerCertCommitment>,
    extensions: Vec<Field<Extension>>,
    transcript_commitments: Vec<Field<TranscriptCommitment>>,
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
            extensions,
            transcript_commitments,
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

        for field in extensions.iter() {
            fields.push((field.id, hasher.hash_separated(&field.data)));
        }

        for field in transcript_commitments.iter() {
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

    /// Returns the transcript commitments.
    pub(crate) fn transcript_commitments(&self) -> impl Iterator<Item = &TranscriptCommitment> {
        self.transcript_commitments.iter().map(|field| &field.data)
    }
}

/// An attestation document.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
