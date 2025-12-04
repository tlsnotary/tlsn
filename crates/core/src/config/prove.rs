//! Proving configuration.

use rangeset::{
    ops::UnionMut,
    set::{RangeSet, ToRangeSet},
};
use serde::{Deserialize, Serialize};

use crate::transcript::{Direction, Transcript, TranscriptCommitConfig, TranscriptCommitRequest};

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

    /// Returns the sent and received ranges of the transcript to be revealed,
    /// respectively.
    pub fn reveal(&self) -> Option<&(RangeSet<usize>, RangeSet<usize>)> {
        self.reveal.as_ref()
    }

    /// Returns the transcript commitment configuration.
    pub fn transcript_commit(&self) -> Option<&TranscriptCommitConfig> {
        self.transcript_commit.as_ref()
    }

    /// Returns a request.
    pub fn to_request(&self) -> ProveRequest {
        ProveRequest {
            server_identity: self.server_identity,
            reveal: self.reveal.clone(),
            transcript_commit: self
                .transcript_commit
                .clone()
                .map(|config| config.to_request()),
        }
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
    ) -> Result<&mut Self, ProveConfigError> {
        let idx = ranges.to_range_set();

        if idx.end().unwrap_or(0) > self.transcript.len_of_direction(direction) {
            return Err(ProveConfigError(ErrorRepr::IndexOutOfBounds {
                direction,
                actual: idx.end().unwrap_or(0),
                len: self.transcript.len_of_direction(direction),
            }));
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
    ) -> Result<&mut Self, ProveConfigError> {
        self.reveal(Direction::Sent, ranges)
    }

    /// Reveals all of the sent data transcript.
    pub fn reveal_sent_all(&mut self) -> Result<&mut Self, ProveConfigError> {
        let len = self.transcript.len_of_direction(Direction::Sent);
        let (sent, _) = self.reveal.get_or_insert_default();
        sent.union_mut(&(0..len));
        Ok(self)
    }

    /// Reveals the given ranges of the received data transcript.
    pub fn reveal_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, ProveConfigError> {
        self.reveal(Direction::Received, ranges)
    }

    /// Reveals all of the received data transcript.
    pub fn reveal_recv_all(&mut self) -> Result<&mut Self, ProveConfigError> {
        let len = self.transcript.len_of_direction(Direction::Received);
        let (_, recv) = self.reveal.get_or_insert_default();
        recv.union_mut(&(0..len));
        Ok(self)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ProveConfig, ProveConfigError> {
        Ok(ProveConfig {
            server_identity: self.server_identity,
            reveal: self.reveal,
            transcript_commit: self.transcript_commit,
        })
    }
}

/// Request to prove statements about the connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequest {
    server_identity: bool,
    reveal: Option<(RangeSet<usize>, RangeSet<usize>)>,
    transcript_commit: Option<TranscriptCommitRequest>,
}

impl ProveRequest {
    /// Returns `true` if the server identity is to be proven.
    pub fn server_identity(&self) -> bool {
        self.server_identity
    }

    /// Returns the sent and received ranges of the transcript to be revealed,
    /// respectively.
    pub fn reveal(&self) -> Option<&(RangeSet<usize>, RangeSet<usize>)> {
        self.reveal.as_ref()
    }

    /// Returns the transcript commitment configuration.
    pub fn transcript_commit(&self) -> Option<&TranscriptCommitRequest> {
        self.transcript_commit.as_ref()
    }
}

/// Error for [`ProveConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProveConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("range is out of bounds of the transcript ({direction}): {actual} > {len}")]
    IndexOutOfBounds {
        direction: Direction,
        actual: usize,
        len: usize,
    },
}
