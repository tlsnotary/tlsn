//! Proving configuration.

use mpz_predicate::Pred;
use rangeset::set::{RangeSet, ToRangeSet};
use serde::{Deserialize, Serialize};

use crate::transcript::{Direction, Transcript, TranscriptCommitConfig, TranscriptCommitRequest};

/// Configuration for a predicate to prove over transcript data.
///
/// A predicate is a boolean constraint that operates on transcript bytes.
/// The prover proves in ZK that the predicate evaluates to true.
///
/// The predicate itself encodes which byte indices it operates on via its
/// atomic comparisons (e.g., `gte(42, threshold)` operates on byte index 42).
#[derive(Debug, Clone)]
pub struct PredicateConfig {
    /// Human-readable name for the predicate (sent to verifier as sanity
    /// check).
    name: String,
    /// Direction of transcript data the predicate operates on.
    direction: Direction,
    /// The predicate to prove.
    predicate: Pred,
}

impl PredicateConfig {
    /// Creates a new predicate configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for the predicate.
    /// * `direction` - Whether the predicate operates on sent or received data.
    /// * `predicate` - The predicate to prove.
    pub fn new(name: impl Into<String>, direction: Direction, predicate: Pred) -> Self {
        Self {
            name: name.into(),
            direction,
            predicate,
        }
    }

    /// Returns the predicate name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the direction of transcript data.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Returns the predicate.
    pub fn predicate(&self) -> &Pred {
        &self.predicate
    }

    /// Returns the transcript byte indices this predicate operates on.
    pub fn indices(&self) -> Vec<usize> {
        self.predicate.indices()
    }

    /// Converts to a request (wire format).
    pub fn to_request(&self) -> PredicateRequest {
        let indices: RangeSet<usize> = self
            .predicate
            .indices()
            .into_iter()
            .map(|idx| idx..idx + 1)
            .collect();
        PredicateRequest {
            name: self.name.clone(),
            direction: self.direction,
            indices,
        }
    }
}

/// Wire format for predicate proving request.
///
/// Contains only the predicate name and indices - the verifier is expected
/// to know which predicate corresponds to the name from out-of-band agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateRequest {
    /// Human-readable name for the predicate.
    name: String,
    /// Direction of transcript data the predicate operates on.
    direction: Direction,
    /// Transcript byte indices the predicate operates on.
    indices: RangeSet<usize>,
}

impl PredicateRequest {
    /// Returns the predicate name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the direction of transcript data.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Returns the transcript byte indices as a RangeSet.
    pub fn indices(&self) -> &RangeSet<usize> {
        &self.indices
    }
}

/// Configuration to prove information to the verifier.
#[derive(Debug, Clone)]
pub struct ProveConfig {
    server_identity: bool,
    reveal: Option<(RangeSet<usize>, RangeSet<usize>)>,
    transcript_commit: Option<TranscriptCommitConfig>,
    predicates: Vec<PredicateConfig>,
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

    /// Returns the predicate configurations.
    pub fn predicates(&self) -> &[PredicateConfig] {
        &self.predicates
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
            predicates: self.predicates.iter().map(|p| p.to_request()).collect(),
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
    predicates: Vec<PredicateConfig>,
}

impl<'a> ProveConfigBuilder<'a> {
    /// Creates a new builder.
    pub fn new(transcript: &'a Transcript) -> Self {
        Self {
            transcript,
            server_identity: false,
            reveal: None,
            transcript_commit: None,
            predicates: Vec::new(),
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

    /// Adds a predicate to prove over transcript data.
    ///
    /// The predicate encodes which byte indices it operates on via its atomic
    /// comparisons (e.g., `gte(42, threshold)` operates on byte index 42).
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for the predicate (sent to verifier as
    ///   sanity check).
    /// * `direction` - Whether the predicate operates on sent or received data.
    /// * `predicate` - The predicate to prove.
    pub fn predicate(
        &mut self,
        name: impl Into<String>,
        direction: Direction,
        predicate: Pred,
    ) -> Result<&mut Self, ProveConfigError> {
        let indices = predicate.indices();

        // Predicate must reference at least one transcript byte.
        let last_idx = *indices
            .last()
            .ok_or(ProveConfigError(ErrorRepr::EmptyPredicate))?;

        // Since indices are sorted, only check the last one for bounds.
        let transcript_len = self.transcript.len_of_direction(direction);
        if last_idx >= transcript_len {
            return Err(ProveConfigError(ErrorRepr::IndexOutOfBounds {
                direction,
                actual: last_idx,
                len: transcript_len,
            }));
        }

        self.predicates
            .push(PredicateConfig::new(name, direction, predicate));
        Ok(self)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ProveConfig, ProveConfigError> {
        Ok(ProveConfig {
            server_identity: self.server_identity,
            reveal: self.reveal,
            transcript_commit: self.transcript_commit,
            predicates: self.predicates,
        })
    }
}

/// Request to prove statements about the connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequest {
    server_identity: bool,
    reveal: Option<(RangeSet<usize>, RangeSet<usize>)>,
    transcript_commit: Option<TranscriptCommitRequest>,
    predicates: Vec<PredicateRequest>,
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

    /// Returns the predicate requests.
    pub fn predicates(&self) -> &[PredicateRequest] {
        &self.predicates
    }
}

/// Error for [`ProveConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProveConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("index out of bounds for {direction} transcript: {actual} >= {len}")]
    IndexOutOfBounds {
        direction: Direction,
        actual: usize,
        len: usize,
    },
    #[error("predicate must reference at least one transcript byte")]
    EmptyPredicate,
}
