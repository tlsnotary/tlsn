//! TLSNotary core library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod connection;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod hash;
pub mod merkle;
pub mod transcript;

use rangeset::ToRangeSet;
use serde::{Deserialize, Serialize};

use crate::{
    connection::{ServerCertData, ServerName},
    transcript::{
        Direction, Idx, PartialTranscript, Transcript, TranscriptCommitConfig,
        TranscriptCommitRequest, TranscriptCommitment, TranscriptSecret,
    },
};

/// Configuration to prove information to the verifier.
#[derive(Debug, Clone)]
pub struct ProveConfig {
    server_identity: bool,
    transcript: Option<PartialTranscript>,
    transcript_commit: Option<TranscriptCommitConfig>,
}

impl ProveConfig {
    /// Creates a new builder.
    pub fn builder(transcript: &Transcript) -> ProveConfigBuilder {
        ProveConfigBuilder::new(transcript)
    }

    /// Returns `true` if the server identity is to be proven.
    pub fn server_identity(&self) -> bool {
        self.server_identity
    }

    /// Returns the transcript to be proven.
    pub fn transcript(&self) -> Option<&PartialTranscript> {
        self.transcript.as_ref()
    }

    /// Returns the transcript commitment configuration.
    pub fn transcript_commit(&self) -> Option<&TranscriptCommitConfig> {
        self.transcript_commit.as_ref()
    }
}

/// Builder for [`ProveConfig`].
#[derive(Debug)]
pub struct ProveConfigBuilder<'a> {
    transcript: &'a Transcript,
    server_identity: bool,
    reveal_sent: Idx,
    reveal_recv: Idx,
    transcript_commit: Option<TranscriptCommitConfig>,
}

impl<'a> ProveConfigBuilder<'a> {
    /// Creates a new builder.
    pub fn new(transcript: &'a Transcript) -> Self {
        Self {
            transcript,
            server_identity: false,
            reveal_sent: Idx::default(),
            reveal_recv: Idx::default(),
            transcript_commit: None,
        }
    }

    /// Proves the server identity.
    pub fn server_identity(&mut self) -> &mut Self {
        self.server_identity = true;
        self
    }

    /// Configures transcript commitments.
    pub fn transcript_commit(&mut self, transcript_commit: TranscriptCommitConfig) -> &mut Self {
        self.transcript_commit = Some(transcript_commit);
        self
    }

    /// Reveals the given ranges of the transcript.
    pub fn reveal(
        &mut self,
        direction: Direction,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, ProveConfigBuilderError> {
        let idx = Idx::new(ranges.to_range_set());

        if idx.end() > self.transcript.len_of_direction(direction) {
            return Err(ProveConfigBuilderError(
                ProveConfigBuilderErrorRepr::IndexOutOfBounds {
                    direction,
                    actual: idx.end(),
                    len: self.transcript.len_of_direction(direction),
                },
            ));
        }

        match direction {
            Direction::Sent => self.reveal_sent.union_mut(&idx),
            Direction::Received => self.reveal_recv.union_mut(&idx),
        }
        Ok(self)
    }

    /// Reveals the given ranges of the sent data transcript.
    pub fn reveal_sent(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, ProveConfigBuilderError> {
        self.reveal(Direction::Sent, ranges)
    }

    /// Reveals the given ranges of the received data transcript.
    pub fn reveal_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, ProveConfigBuilderError> {
        self.reveal(Direction::Received, ranges)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ProveConfig, ProveConfigBuilderError> {
        let transcript = if !self.reveal_sent.is_empty() || !self.reveal_recv.is_empty() {
            Some(
                self.transcript
                    .to_partial(self.reveal_sent, self.reveal_recv),
            )
        } else {
            None
        };

        Ok(ProveConfig {
            server_identity: self.server_identity,
            transcript,
            transcript_commit: self.transcript_commit,
        })
    }
}

/// Error for [`ProveConfigBuilder`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProveConfigBuilderError(#[from] ProveConfigBuilderErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ProveConfigBuilderErrorRepr {
    #[error("range is out of bounds of the transcript ({direction}): {actual} > {len}")]
    IndexOutOfBounds {
        direction: Direction,
        actual: usize,
        len: usize,
    },
}

/// Configuration to verify information from the prover.
#[derive(Debug, Default, Clone)]
pub struct VerifyConfig {}

impl VerifyConfig {
    /// Creates a new builder.
    pub fn builder() -> VerifyConfigBuilder {
        VerifyConfigBuilder::new()
    }
}

/// Builder for [`VerifyConfig`].
#[derive(Debug, Default)]
pub struct VerifyConfigBuilder {}

impl VerifyConfigBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {}
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<VerifyConfig, VerifyConfigBuilderError> {
        Ok(VerifyConfig {})
    }
}

/// Error for [`VerifyConfigBuilder`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct VerifyConfigBuilderError(#[from] VerifyConfigBuilderErrorRepr);

#[derive(Debug, thiserror::Error)]
enum VerifyConfigBuilderErrorRepr {}

/// Payload sent to the verifier.
#[doc(hidden)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvePayload {
    /// Server identity data.
    pub server_identity: Option<(ServerName, ServerCertData)>,
    /// Transcript data.
    pub transcript: Option<PartialTranscript>,
    /// Transcript commitment configuration.
    pub transcript_commit: Option<TranscriptCommitRequest>,
}

/// Prover output.
pub struct ProverOutput {
    /// Transcript commitments.
    pub transcript_commitments: Vec<TranscriptCommitment>,
    /// Transcript commitment secrets.
    pub transcript_secrets: Vec<TranscriptSecret>,
}

opaque_debug::implement!(ProverOutput);

/// Verifier output.
pub struct VerifierOutput {
    /// Server identity.
    pub server_name: Option<ServerName>,
    /// Transcript data.
    pub transcript: Option<PartialTranscript>,
    /// Transcript commitments.
    pub transcript_commitments: Vec<TranscriptCommitment>,
}

opaque_debug::implement!(VerifierOutput);
