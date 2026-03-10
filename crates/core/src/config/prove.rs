//! Proving configuration.

use rangeset::{
    iter::{FromRangeIterator, IntoRangeIterator},
    set::RangeSet,
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
        ranges: impl IntoRangeIterator<usize>,
    ) -> Result<&mut Self, ProveConfigError> {
        self.reveal_inner(direction, RangeSet::from_range_iter(ranges))
    }

    fn reveal_inner(
        &mut self,
        direction: Direction,
        idx: RangeSet<usize>,
    ) -> Result<&mut Self, ProveConfigError> {
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
        ranges: impl IntoRangeIterator<usize>,
    ) -> Result<&mut Self, ProveConfigError> {
        self.reveal_inner(Direction::Sent, RangeSet::from_range_iter(ranges))
    }

    /// Reveals all of the sent data transcript.
    pub fn reveal_sent_all(&mut self) -> Result<&mut Self, ProveConfigError> {
        let len = self.transcript.len_of_direction(Direction::Sent);
        let (sent, _) = self.reveal.get_or_insert_default();
        sent.union_mut(0..len);
        Ok(self)
    }

    /// Reveals the given ranges of the received data transcript.
    pub fn reveal_recv(
        &mut self,
        ranges: impl IntoRangeIterator<usize>,
    ) -> Result<&mut Self, ProveConfigError> {
        self.reveal_inner(Direction::Received, RangeSet::from_range_iter(ranges))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript() -> Transcript {
        Transcript::new(vec![0u8; 100], vec![0u8; 200])
    }

    #[test]
    fn test_build_default() {
        let t = transcript();
        let config = ProveConfig::builder(&t).build().unwrap();

        assert!(!config.server_identity());
        assert!(config.reveal().is_none());
        assert!(config.transcript_commit().is_none());
    }

    #[test]
    fn test_server_identity() {
        let t = transcript();
        let mut builder = ProveConfig::builder(&t);
        builder.server_identity();
        let config = builder.build().unwrap();

        assert!(config.server_identity());
    }

    #[test]
    fn test_reveal_sent() {
        let t = transcript();
        let mut builder = ProveConfig::builder(&t);
        builder.reveal_sent(0..50).unwrap();
        let config = builder.build().unwrap();

        let (sent, recv) = config.reveal().unwrap();
        assert_eq!(sent.len(), 50);
        assert_eq!(recv.len(), 0);
    }

    #[test]
    fn test_reveal_recv() {
        let t = transcript();
        let mut builder = ProveConfig::builder(&t);
        builder.reveal_recv(10..100).unwrap();
        let config = builder.build().unwrap();

        let (sent, recv) = config.reveal().unwrap();
        assert_eq!(sent.len(), 0);
        assert_eq!(recv.len(), 90);
    }

    #[test]
    fn test_reveal_sent_all() {
        let t = transcript();
        let mut builder = ProveConfig::builder(&t);
        builder.reveal_sent_all().unwrap();
        let config = builder.build().unwrap();

        let (sent, _) = config.reveal().unwrap();
        assert_eq!(sent.len(), 100);
    }

    #[test]
    fn test_reveal_recv_all() {
        let t = transcript();
        let mut builder = ProveConfig::builder(&t);
        builder.reveal_recv_all().unwrap();
        let config = builder.build().unwrap();

        let (_, recv) = config.reveal().unwrap();
        assert_eq!(recv.len(), 200);
    }

    #[test]
    fn test_reveal_sent_out_of_bounds() {
        let t = transcript();
        let mut builder = ProveConfig::builder(&t);
        let err = builder.reveal_sent(0..101);

        assert!(err.is_err());
    }

    #[test]
    fn test_reveal_recv_out_of_bounds() {
        let t = transcript();
        let mut builder = ProveConfig::builder(&t);
        let err = builder.reveal_recv(0..201);

        assert!(err.is_err());
    }

    #[test]
    fn test_to_request() {
        let t = transcript();
        let mut builder = ProveConfig::builder(&t);
        builder.server_identity();
        builder.reveal_sent(0..10).unwrap();
        let config = builder.build().unwrap();

        let request = config.to_request();
        assert!(request.server_identity());
        assert!(request.reveal().is_some());
    }
}
