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
pub mod webpki;
pub use rangeset;
pub(crate) mod display;

use rangeset::{RangeSet, ToRangeSet, UnionMut};
use serde::{Deserialize, Serialize};

use crate::{
    connection::{HandshakeData, ServerName},
    transcript::{
        Direction, PartialTranscript, Transcript, TranscriptCommitConfig, TranscriptCommitRequest,
        TranscriptCommitment, TranscriptSecret,
    },
};

/// Configuration to prove information to the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveConfig {
    server_identity: bool,
    reveal: Option<(RangeSet<usize>, RangeSet<usize>)>,
    transcript_commit: Option<TranscriptCommitConfig>,
}

impl ProveConfig {
    /// Creates a new builder.
    pub fn builder(transcript: &Transcript) -> ProveConfigBuilder<'_> {
        ProveConfigBuilder::new(transcript)
    }

    /// Returns `true` if the server identity is to be proven.
    pub fn server_identity(&self) -> bool {
        self.server_identity
    }

    /// Returns the ranges of the transcript to be revealed.
    pub fn reveal(&self) -> Option<&(RangeSet<usize>, RangeSet<usize>)> {
        self.reveal.as_ref()
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
    reveal: Option<(RangeSet<usize>, RangeSet<usize>)>,
    transcript_commit: Option<TranscriptCommitConfig>,
}

impl<'a> ProveConfigBuilder<'a> {
    /// Creates a new builder.
    pub fn new(transcript: &'a Transcript) -> Self {
        Self {
            transcript,
            server_identity: false,
            reveal: None,
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
        let idx = ranges.to_range_set();

        if idx.end().unwrap_or(0) > self.transcript.len_of_direction(direction) {
            return Err(ProveConfigBuilderError(
                ProveConfigBuilderErrorRepr::IndexOutOfBounds {
                    direction,
                    actual: idx.end().unwrap_or(0),
                    len: self.transcript.len_of_direction(direction),
                },
            ));
        }

        let (sent, recv) = self.reveal.get_or_insert_default();
        match direction {
            Direction::Sent => sent.union_mut(&idx),
            Direction::Received => recv.union_mut(&idx),
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

    /// Reveals the full transcript range for a given direction.
    pub fn reveal_all(
        &mut self,
        direction: Direction,
    ) -> Result<&mut Self, ProveConfigBuilderError> {
        let len = self.transcript.len_of_direction(direction);
        self.reveal(direction, &(0..len))
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ProveConfig, ProveConfigBuilderError> {
        Ok(ProveConfig {
            server_identity: self.server_identity,
            reveal: self.reveal,
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
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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

/// Request to prove statements about the connection.
#[doc(hidden)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProveRequest {
    /// Handshake data.
    pub handshake: Option<(ServerName, HandshakeData)>,
    /// Transcript data.
    pub transcript: Option<PartialTranscript>,
    /// Transcript commitment configuration.
    pub transcript_commit: Option<TranscriptCommitRequest>,
}

impl ProveRequest {
    /// Creates a new prove payload.
    ///
    /// # Arguments
    ///
    /// * `config` - The prove config.
    /// * `transcript` - The partial transcript.
    /// * `handshake` - The server name and handshake data.
    pub fn new(
        config: &ProveConfig,
        transcript: Option<PartialTranscript>,
        handshake: Option<(ServerName, HandshakeData)>,
    ) -> Self {
        let transcript_commit = config.transcript_commit().map(|config| config.to_request());

        Self {
            handshake,
            transcript,
            transcript_commit,
        }
    }
}

/// Prover output.
#[derive(Serialize, Deserialize)]
pub struct ProverOutput {
    /// Transcript commitments.
    pub transcript_commitments: Vec<TranscriptCommitment>,
    /// Transcript commitment secrets.
    pub transcript_secrets: Vec<TranscriptSecret>,
}

opaque_debug::implement!(ProverOutput);

/// Verifier output.
#[derive(Serialize, Deserialize)]
pub struct VerifierOutput {
    /// Server identity.
    pub server_name: Option<ServerName>,
    /// Transcript data.
    pub transcript: Option<PartialTranscript>,
    /// Transcript commitments.
    pub transcript_commitments: Vec<TranscriptCommitment>,
}

opaque_debug::implement!(VerifierOutput);
