use utils::range::ToRangeSet;

use crate::{
    hash::HashAlgorithm, substring::SubstringCommitmentKind, transcript::SubsequenceIdx, Direction,
};

/// Configuration for substrings commitments.
#[derive(Debug, Clone)]
pub struct SubstringsCommitConfig {
    pub(crate) commits: Vec<(SubsequenceIdx, SubstringCommitmentKind)>,
}

impl SubstringsCommitConfig {
    /// Creates a new builder.
    pub fn builder() -> SubstringsCommitConfigBuilder {
        SubstringsCommitConfigBuilder::default()
    }
}

/// A builder for [`SubstringsCommitConfig`].
///
/// The default hash algorithm is [`HashAlgorithm::Blake3`] and the default kind
/// is [`SubstringCommitmentKind::Encoding`].
#[derive(Debug)]
pub struct SubstringsCommitConfigBuilder {
    default_hash_alg: HashAlgorithm,
    default_kind: SubstringCommitmentKind,
    commits: Vec<(SubsequenceIdx, SubstringCommitmentKind)>,
}

impl Default for SubstringsCommitConfigBuilder {
    fn default() -> Self {
        SubstringsCommitConfigBuilder {
            default_hash_alg: HashAlgorithm::Blake3,
            default_kind: SubstringCommitmentKind::Encoding,
            commits: vec![],
        }
    }
}

impl SubstringsCommitConfigBuilder {
    /// Sets the default hash algorithm to use.
    pub fn default_hash_alg(&mut self, default_hash_alg: HashAlgorithm) -> &mut Self {
        self.default_hash_alg = default_hash_alg;
        self
    }

    /// Sets the default kind of commitment to use.
    pub fn default_kind(&mut self, default_kind: SubstringCommitmentKind) -> &mut Self {
        self.default_kind = default_kind;
        self
    }

    /// Adds a commitment.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges of the commitment.
    /// * `direction` - The direction of the transcript.
    /// * `kind` - The kind of commitment.
    pub fn commit_with_kind(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
        mut kind: SubstringCommitmentKind,
    ) -> &mut Self {
        let seq = SubsequenceIdx {
            direction,
            ranges: ranges.to_range_set(),
        };

        if let SubstringCommitmentKind::Hash { alg } = &mut kind {
            if alg.is_none() {
                *alg = Some(self.default_hash_alg);
            }
        }

        self.commits.push((seq, kind));
        self
    }

    /// Adds a commitment with the default kind.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges of the commitment.
    /// * `direction` - The direction of the transcript.
    pub fn commit(&mut self, ranges: &dyn ToRangeSet<usize>, direction: Direction) -> &mut Self {
        self.commit_with_kind(ranges, direction, self.default_kind)
    }

    /// Builds the configuration.
    pub fn build(self) -> SubstringsCommitConfig {
        SubstringsCommitConfig {
            commits: self.commits,
        }
    }
}

/// Configuration for a substrings proof.
#[derive(Debug, Clone)]
pub struct SubstringsProofConfig {
    pub(crate) seqs: Vec<SubsequenceIdx>,
}

impl SubstringsProofConfig {
    /// Creates a new builder.
    pub fn builder() -> SubstringsProofConfigBuilder {
        SubstringsProofConfigBuilder::default()
    }
}

/// A builder for [`SubstringsProofConfig`].
pub struct SubstringsProofConfigBuilder {
    seqs: Vec<SubsequenceIdx>,
}

impl Default for SubstringsProofConfigBuilder {
    fn default() -> Self {
        SubstringsProofConfigBuilder { seqs: vec![] }
    }
}

impl SubstringsProofConfigBuilder {
    /// Reveals the given ranges in the transcript.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    /// * `direction` - The direction of the transcript.
    pub fn reveal(&mut self, ranges: &dyn ToRangeSet<usize>, direction: Direction) -> &mut Self {
        let seq = SubsequenceIdx {
            direction,
            ranges: ranges.to_range_set(),
        };

        self.seqs.push(seq);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> SubstringsProofConfig {
        SubstringsProofConfig { seqs: self.seqs }
    }
}
