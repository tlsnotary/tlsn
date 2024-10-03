//! TLSNotary core library.
//!
//! # Introduction
//!
//! This library provides core functionality for the TLSNotary **attestation**
//! protocol, including some more general types which are useful outside
//! of attestations.
//!
//! Once the MPC-TLS protocol has been completed the Prover holds a collection
//! of commitments pertaining to the TLS connection. Most importantly, the
//! Prover is committed to the [`ServerName`](crate::connection::ServerName),
//! and the [`Transcript`](crate::transcript::Transcript) of application data.
//! Subsequently, the Prover can request an
//! [`Attestation`](crate::attestation::Attestation) from the Notary who will
//! include the commitments as well as any additional information which may be
//! useful to an attestation Verifier.
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
//! # Committing to the transcript
//!
//! The MPC-TLS protocol produces commitments to the entire transcript of
//! application data. However, we may want to disclose only a subset of the data
//! in a presentation. Prior to attestation, the Prover has the opportunity to
//! slice and dice the commitments into smaller sections which can be
//! selectively disclosed. Additionally, the Prover may want to use different
//! commitment schemes depending on the context they expect to disclose.
//!
//! The primary API for this process is the
//! [`TranscriptCommitConfigBuilder`](crate::transcript::TranscriptCommitConfigBuilder)
//! which is used to build up a configuration.
//!
//! Currently, only the
//! [`Encoding`](crate::transcript::TranscriptCommitmentKind::Encoding)
//! commitment kind is supported. In the future you will be able to acquire hash
//! commitments directly to the transcript data.
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
//! Upon being issued an attestation, the Prover will also hold a corresponding
//! [`Secrets`] which contains all private information. This pair can be stored
//! and used later to construct a
//! [`Presentation`](crate::presentation::Presentation), [see
//! below](#constructing-a-presentation).
//!
//! # Issuing an attestation
//!
//! Upon receiving a request, the Notary can issue an
//! [`Attestation`](crate::attestation::Attestation) which can be configured
//! using the associated
//! [builder](crate::attestation::AttestationConfigBuilder).
//!
//! The Notary's [`CryptoProvider`] must be configured with an appropriate
//! signing key for attestations. See
//! [`SignerProvider`](crate::signing::SignerProvider) for more information.
//!
//! # Constructing a presentation
//!
//! A Prover can use an [`Attestation`](crate::attestation::Attestation) and the
//! corresponding [`Secrets`] to construct a verifiable
//! [`Presentation`](crate::presentation::Presentation).
//!
//! ```no_run
//! # use tlsn_core::presentation::Presentation;
//! # use tlsn_core::attestation::Attestation;
//! # use tlsn_core::transcript::{TranscriptCommitmentKind, Direction};
//! # use tlsn_core::{Secrets, CryptoProvider};
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
//!     .default_kind(TranscriptCommitmentKind::Encoding)
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
//! # use tlsn_core::presentation::{Presentation, PresentationOutput};
//! # use tlsn_core::signing::VerifyingKey;
//! # use tlsn_core::CryptoProvider;
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

pub mod attestation;
pub mod connection;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod hash;
pub(crate) mod index;
pub(crate) mod merkle;
pub mod presentation;
mod provider;
pub mod request;
mod secrets;
pub(crate) mod serialize;
pub mod signing;
pub mod transcript;

pub use provider::CryptoProvider;
pub use secrets::Secrets;
