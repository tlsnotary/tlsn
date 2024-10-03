//! Verifiable presentation.
//!
//! We borrow the term "presentation" from the
//! [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/#presentations-0).
//!
//! > Data derived from one or more verifiable credentials, issued by one or
//! > more issuers, that is shared with a specific verifier. A verifiable
//! > presentation is a tamper-evident presentation encoded in such a way that
//! > authorship of the data can be trusted after a process of cryptographic
//! > verification. Certain types of verifiable presentations might contain data
//! > that is synthesized from, but do not contain, the original verifiable
//! > credentials (for example, zero-knowledge proofs).
//!
//! Instead of a credential, a presentation in this context is a proof of an
//! attestation from a Notary along with additional selectively disclosed
//! information about the TLS connection such as the server's identity and the
//! application data communicated with the server.
//!
//! A presentation is self-contained and can be verified by a Verifier without
//! needing access to external data. The Verifier need only check that the key
//! used to sign the attestation, referred to as a [`VerifyingKey`], is from a
//! Notary they trust. See an [example](crate#verifying-a-presentation) in the
//! crate level documentation.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::{Attestation, AttestationError, AttestationProof},
    connection::{ConnectionInfo, ServerIdentityProof, ServerIdentityProofError, ServerName},
    signing::VerifyingKey,
    transcript::{PartialTranscript, TranscriptProof, TranscriptProofError},
    CryptoProvider,
};

/// A verifiable presentation.
///
/// See the [module level documentation](crate::presentation) for more
/// information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Presentation {
    attestation: AttestationProof,
    identity: Option<ServerIdentityProof>,
    transcript: Option<TranscriptProof>,
}

impl Presentation {
    /// Creates a new builder.
    pub fn builder<'a>(
        provider: &'a CryptoProvider,
        attestation: &'a Attestation,
    ) -> PresentationBuilder<'a> {
        PresentationBuilder::new(provider, attestation)
    }

    /// Returns the verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.attestation.verifying_key()
    }

    /// Verifies the presentation.
    pub fn verify(
        self,
        provider: &CryptoProvider,
    ) -> Result<PresentationOutput, PresentationError> {
        let Self {
            attestation,
            identity,
            transcript,
        } = self;

        let attestation = attestation.verify(provider)?;

        let server_name = identity
            .map(|identity| {
                identity.verify_with_provider(
                    provider,
                    attestation.body.connection_info().time,
                    attestation.body.server_ephemeral_key(),
                    attestation.body.cert_commitment(),
                )
            })
            .transpose()?;

        let transcript = transcript
            .map(|transcript| transcript.verify_with_provider(provider, &attestation.body))
            .transpose()?;

        let connection_info = attestation.body.connection_info().clone();

        Ok(PresentationOutput {
            attestation,
            server_name,
            connection_info,
            transcript,
        })
    }
}

/// Output of a verified [`Presentation`].
#[derive(Debug)]
#[non_exhaustive]
pub struct PresentationOutput {
    /// Verified attestation.
    pub attestation: Attestation,
    /// Authenticated server name.
    pub server_name: Option<ServerName>,
    /// Connection information.
    pub connection_info: ConnectionInfo,
    /// Authenticated transcript data.
    pub transcript: Option<PartialTranscript>,
}

/// Builder for [`Presentation`].
pub struct PresentationBuilder<'a> {
    provider: &'a CryptoProvider,
    attestation: &'a Attestation,
    identity_proof: Option<ServerIdentityProof>,
    transcript_proof: Option<TranscriptProof>,
}

impl<'a> PresentationBuilder<'a> {
    pub(crate) fn new(provider: &'a CryptoProvider, attestation: &'a Attestation) -> Self {
        Self {
            provider,
            attestation,
            identity_proof: None,
            transcript_proof: None,
        }
    }

    /// Includes a server identity proof.
    pub fn identity_proof(&mut self, proof: ServerIdentityProof) -> &mut Self {
        self.identity_proof = Some(proof);
        self
    }

    /// Includes a transcript proof.
    pub fn transcript_proof(&mut self, proof: TranscriptProof) -> &mut Self {
        self.transcript_proof = Some(proof);
        self
    }

    /// Builds the presentation.
    pub fn build(self) -> Result<Presentation, PresentationBuilderError> {
        let attestation = AttestationProof::new(self.provider, self.attestation)?;

        Ok(Presentation {
            attestation,
            identity: self.identity_proof,
            transcript: self.transcript_proof,
        })
    }
}

/// Error for [`PresentationBuilder`].
#[derive(Debug, thiserror::Error)]
pub struct PresentationBuilderError {
    kind: BuilderErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

#[derive(Debug)]
enum BuilderErrorKind {
    Attestation,
}

impl fmt::Display for PresentationBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("presentation builder error: ")?;

        match self.kind {
            BuilderErrorKind::Attestation => f.write_str("attestation error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<AttestationError> for PresentationBuilderError {
    fn from(error: AttestationError) -> Self {
        Self {
            kind: BuilderErrorKind::Attestation,
            source: Some(Box::new(error)),
        }
    }
}

/// Error for [`Presentation`].
#[derive(Debug, thiserror::Error)]
pub struct PresentationError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

#[derive(Debug)]
enum ErrorKind {
    Attestation,
    Identity,
    Transcript,
}

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("presentation error: ")?;

        match self.kind {
            ErrorKind::Attestation => f.write_str("attestation error")?,
            ErrorKind::Identity => f.write_str("server identity error")?,
            ErrorKind::Transcript => f.write_str("transcript error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<AttestationError> for PresentationError {
    fn from(error: AttestationError) -> Self {
        Self {
            kind: ErrorKind::Attestation,
            source: Some(Box::new(error)),
        }
    }
}

impl From<ServerIdentityProofError> for PresentationError {
    fn from(error: ServerIdentityProofError) -> Self {
        Self {
            kind: ErrorKind::Identity,
            source: Some(Box::new(error)),
        }
    }
}

impl From<TranscriptProofError> for PresentationError {
    fn from(error: TranscriptProofError) -> Self {
        Self {
            kind: ErrorKind::Transcript,
            source: Some(Box::new(error)),
        }
    }
}
