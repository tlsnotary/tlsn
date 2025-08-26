//! Encoding commitment protocol.

use crate::{EncodingMemory, commit::transcript::TranscriptRefs};
use mpz_garble_core::Delta;
use mpz_memory_core::binary::Binary;
use rand::Rng;
use rangeset::{RangeSet, Subset};
use serde::{Deserialize, Serialize};
use std::ops::Range;
use tlsn_core::{
    hash::{Blake3, HashAlgId, HashAlgorithm, Keccak256, Sha256, TypedHash},
    transcript::{
        Direction, Idx,
        encoding::{
            Encoder, EncoderSecret, EncodingProvider, EncodingProviderError, EncodingTree,
            EncodingTreeError, new_encoder,
        },
    },
};

/// Bytes of encoding, per byte.
pub(crate) const ENCODING_SIZE: usize = 128;

/// The encoding adjustments.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Encodings {
    sent: Vec<u8>,
    recv: Vec<u8>,
}

/// Creates encoding commitments.
#[derive(Debug)]
pub(crate) struct EncodingCreator {
    id: Option<HashAlgId>,
    sent: RangeSet<usize>,
    recv: RangeSet<usize>,
}

impl EncodingCreator {
    /// Creates a new encoding creator.
    ///
    /// # Arguments
    ///
    /// * `id` - The id of the hash algorithm.
    /// * `sent` - The encoding ranges for the sent transcript.
    /// * `recv` - The encoding ranges for the received transcript.
    pub(crate) fn new(id: Option<HashAlgId>, sent: RangeSet<usize>, recv: RangeSet<usize>) -> Self {
        Self { id, sent, recv }
    }

    /// Receives the encodings using the provided MACs.
    ///
    /// The MACs must be consistent with the global delta used in the encodings.
    ///
    /// # Arguments
    ///
    /// * `encoding_mem` - The encoding memory.
    /// * `encodings` - The encoding adjustments.
    /// * `transcript_refs` - The transcript references.
    pub(crate) fn receive<'a>(
        &self,
        encoding_mem: &mut dyn EncodingMemory<Binary>,
        encodings: Encodings,
        transcript_refs: &TranscriptRefs,
    ) -> Result<(TypedHash, EncodingTree), EncodingError> {
        let Some(id) = self.id else {
            return Err(EncodingError(ErrorRepr::MissingHashId));
        };

        let hasher: &(dyn HashAlgorithm + Send + Sync) = match id {
            HashAlgId::SHA256 => &Sha256::default(),
            HashAlgId::KECCAK256 => &Keccak256::default(),
            HashAlgId::BLAKE3 => &Blake3::default(),
            alg => {
                return Err(EncodingError(ErrorRepr::UnsupportedHashAlg(alg)));
            }
        };

        let Encodings {
            sent: mut sent_adjust,
            recv: mut recv_adjust,
        } = encodings;

        let sent_refs = transcript_refs.get(Direction::Sent, &self.sent);
        let sent = encoding_mem.get_encodings(&sent_refs);

        let recv_refs = transcript_refs.get(Direction::Received, &self.recv);
        let recv: Vec<u8> = encoding_mem.get_encodings(&recv_refs);

        self.adjust(&sent, &recv, &mut sent_adjust, &mut recv_adjust)?;

        let provider = Provider::new(sent_adjust, &self.sent, recv_adjust, &self.recv);
        let idxs: Vec<(Direction, Idx)> = self
            .sent
            .iter_ranges()
            .map(|r| (Direction::Sent, Idx::new(r)))
            .chain(
                self.recv
                    .iter_ranges()
                    .map(|r| (Direction::Received, Idx::new(r))),
            )
            .collect();

        let tree = EncodingTree::new(hasher, idxs.iter(), &provider)?;
        let root = tree.root();

        Ok((root, tree))
    }

    /// Transfers the encodings using the provided seed and keys.
    ///
    /// The keys must be consistent with the global delta used in the encodings.
    ///
    /// # Arguments
    ///
    /// * `encoding_mem` - The encoding memory.
    /// * `delta` -  The global delta.
    /// * `transcript_refs` - The transcript references.
    pub(crate) fn transfer(
        &self,
        encoding_mem: &mut dyn EncodingMemory<Binary>,
        delta: Delta,
        transcript_refs: &TranscriptRefs,
    ) -> Result<(Encodings, EncoderSecret), EncodingError> {
        let secret = EncoderSecret::new(rand::rng().random(), delta.as_block().to_bytes());
        let encoder = new_encoder(&secret);

        let mut sent_zero = Vec::with_capacity(self.sent.len() * ENCODING_SIZE);
        let mut recv_zero = Vec::with_capacity(self.recv.len() * ENCODING_SIZE);

        for range in self.sent.iter_ranges() {
            encoder.encode_range(Direction::Sent, range, &mut sent_zero);
        }

        for range in self.recv.iter_ranges() {
            encoder.encode_range(Direction::Received, range, &mut recv_zero);
        }

        let sent_refs = transcript_refs.get(Direction::Sent, &self.sent);
        let sent = encoding_mem.get_encodings(&sent_refs);

        let recv_refs = transcript_refs.get(Direction::Received, &self.recv);
        let recv: Vec<u8> = encoding_mem.get_encodings(&recv_refs);

        self.adjust(&sent, &recv, &mut sent_zero, &mut recv_zero)?;
        let encodings = Encodings {
            sent: sent_zero,
            recv: recv_zero,
        };

        Ok((encodings, secret))
    }

    /// Adjust encodings by transcript references.
    ///
    /// # Arguments
    ///
    /// * `sent` - The encodings for the sent bytes.
    /// * `recv` - The encodings for the received bytes.
    /// * `sent_adjust` - The adjustment bytes for the encodings of the sent bytes.
    /// * `recv_adjust` - The adjustment bytes for the encodings of the received bytes.
    fn adjust(
        &self,
        sent: &[u8],
        recv: &[u8],
        sent_adjust: &mut [u8],
        recv_adjust: &mut [u8],
    ) -> Result<(), EncodingError> {
        assert_eq!(sent.len() % ENCODING_SIZE, 0);
        assert_eq!(recv.len() % ENCODING_SIZE, 0);

        if sent_adjust.len() != sent.len() {
            return Err(ErrorRepr::IncorrectAdjustCount {
                direction: Direction::Sent,
                expected: sent.len(),
                got: sent_adjust.len(),
            }
            .into());
        }

        if recv_adjust.len() != recv.len() {
            return Err(ErrorRepr::IncorrectAdjustCount {
                direction: Direction::Received,
                expected: recv.len(),
                got: recv_adjust.len(),
            }
            .into());
        }

        sent_adjust
            .iter_mut()
            .zip(sent)
            .for_each(|(adjust, enc)| *adjust ^= enc);
        recv_adjust
            .iter_mut()
            .zip(recv)
            .for_each(|(adjust, enc)| *adjust ^= enc);

        Ok(())
    }
}

#[derive(Debug)]
struct Provider {
    sent: Vec<u8>,
    sent_range: RangeSet<usize>,
    recv: Vec<u8>,
    recv_range: RangeSet<usize>,
}

impl Provider {
    fn new(
        sent: Vec<u8>,
        sent_range: &RangeSet<usize>,
        recv: Vec<u8>,
        recv_range: &RangeSet<usize>,
    ) -> Self {
        assert_eq!(
            sent.len(),
            sent_range.len() * ENCODING_SIZE,
            "length of sent encodings and their index length do not match"
        );
        assert_eq!(
            recv.len(),
            recv_range.len() * ENCODING_SIZE,
            "length of received encodings and their index length do not match"
        );

        Self {
            sent,
            sent_range: sent_range.clone(),
            recv,
            recv_range: recv_range.clone(),
        }
    }

    fn adjust(
        &self,
        direction: Direction,
        range: &Range<usize>,
    ) -> Result<Range<usize>, EncodingProviderError> {
        let internal_range = match direction {
            Direction::Sent => &self.sent_range,
            Direction::Received => &self.recv_range,
        };

        if !range.is_subset(internal_range) {
            return Err(EncodingProviderError);
        }

        let shift = internal_range
            .iter()
            .take_while(|&el| el < range.start)
            .count();

        let translated = Range {
            start: shift,
            end: shift + range.len(),
        };

        Ok(translated)
    }
}

impl EncodingProvider for Provider {
    fn provide_encoding(
        &self,
        direction: Direction,
        range: Range<usize>,
        dest: &mut Vec<u8>,
    ) -> Result<(), EncodingProviderError> {
        let encodings = match direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.recv,
        };

        let range = self.adjust(direction, &range)?;

        let start = range.start * ENCODING_SIZE;
        let end = range.end * ENCODING_SIZE;

        dest.extend_from_slice(&encodings[start..end]);

        Ok(())
    }
}

/// Encoding protocol error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct EncodingError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("encoding protocol error: {0}")]
enum ErrorRepr {
    #[error("incorrect adjustment count for {direction}: expected {expected}, got {got}")]
    IncorrectAdjustCount {
        direction: Direction,
        expected: usize,
        got: usize,
    },
    #[error("encoding tree error: {0}")]
    EncodingTree(EncodingTreeError),
    #[error("missing hash id")]
    MissingHashId,
    #[error("unsupported hash algorithm for encoding commitment: {0}")]
    UnsupportedHashAlg(HashAlgId),
}

impl From<EncodingTreeError> for EncodingError {
    fn from(value: EncodingTreeError) -> Self {
        Self(ErrorRepr::EncodingTree(value))
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use crate::{
        EncodingMemory,
        commit::{
            encoding::{ENCODING_SIZE, EncodingCreator, Encodings, Provider},
            transcript::TranscriptRefs,
        },
    };
    use mpz_core::Block;
    use mpz_garble_core::Delta;
    use mpz_memory_core::{
        FromRaw, Slice, ToRaw, Vector,
        binary::{Binary, U8},
    };
    use rangeset::{RangeSet, UnionMut};
    use rstest::{fixture, rstest};
    use tlsn_core::{
        hash::{HashAlgId, HashProvider},
        transcript::{
            Direction, Idx,
            encoding::{EncodingCommitment, EncodingProvider},
        },
    };

    #[rstest]
    fn test_encoding_adjust(
        index: (RangeSet<usize>, RangeSet<usize>),
        transcript_refs: TranscriptRefs,
    ) {
        let (sent_range, recv_range) = index;

        let creator = EncodingCreator::new(
            Some(HashAlgId::SHA256),
            sent_range.clone(),
            recv_range.clone(),
        );

        let mock_memory: &mut dyn EncodingMemory<Binary> = &mut MockEncodingMemory;
        let delta = Delta::new(Block::ONES);

        let (adjustments, secret) = creator
            .transfer(mock_memory, delta, &transcript_refs)
            .unwrap();

        let (root, tree) = creator
            .receive(mock_memory, adjustments, &transcript_refs)
            .unwrap();

        // Check correctness of encoding protocol now.
        let mut idxs = Vec::new();

        let sent = transcript_refs.get(Direction::Sent, &sent_range);
        let recv = transcript_refs.get(Direction::Received, &recv_range);

        let sent = mock_memory.get_encodings(&sent);
        let recv = mock_memory.get_encodings(&recv);

        idxs.push((Direction::Sent, Idx::new(sent_range)));
        idxs.push((Direction::Received, Idx::new(recv_range)));

        let commitment = EncodingCommitment { root, secret };
        let proof = tree.proof(idxs.iter()).unwrap();

        let (idx_sent, idx_recv) = proof
            .verify_with_provider(&HashProvider::default(), &commitment, &sent, &recv)
            .unwrap();

        assert_eq!(idx_sent, idxs[0].1);
        assert_eq!(idx_recv, idxs[1].1);
    }

    #[rstest]
    fn test_encoding_provider(index: (RangeSet<usize>, RangeSet<usize>), encodings: Encodings) {
        let (sent_range, recv_range) = index;
        let Encodings { sent, recv } = encodings;

        let provider = Provider::new(sent, &sent_range, recv, &recv_range);

        let mut encodings_sent = Vec::new();
        let mut encodings_recv = Vec::new();

        provider
            .provide_encoding(Direction::Sent, 15..21, &mut encodings_sent)
            .unwrap();
        provider
            .provide_encoding(Direction::Received, 50..56, &mut encodings_recv)
            .unwrap();

        let expected_sent = generate_encodings((15..21).into());
        let expected_recv = generate_encodings((50..56).into());

        assert_eq!(expected_sent, encodings_sent);
        assert_eq!(expected_recv, encodings_recv);
    }

    #[fixture]
    fn transcript_refs(index: (RangeSet<usize>, RangeSet<usize>)) -> TranscriptRefs {
        let mut transcript_refs = TranscriptRefs::new(1000, 1000);

        let dummy = |range: Range<usize>| {
            Vector::<U8>::from_raw(Slice::from_range_unchecked(range.start..range.end))
        };

        for range in index.0.iter_ranges() {
            transcript_refs.add(Direction::Sent, &range, dummy(range.clone()));
        }

        for range in index.1.iter_ranges() {
            transcript_refs.add(Direction::Received, &range, dummy(range.clone()));
        }

        transcript_refs
    }

    #[fixture]
    fn encodings(index: (RangeSet<usize>, RangeSet<usize>)) -> Encodings {
        let sent = generate_encodings(index.0);
        let recv = generate_encodings(index.1);

        Encodings { sent, recv }
    }

    #[fixture]
    fn index() -> (RangeSet<usize>, RangeSet<usize>) {
        let mut sent = RangeSet::default();
        sent.union_mut(&(1..8));
        sent.union_mut(&(16..24));
        sent.union_mut(&(32..40));

        let mut recv = RangeSet::default();
        recv.union_mut(&(40..48));
        recv.union_mut(&(56..64));

        (sent, recv)
    }

    #[derive(Clone, Copy)]
    struct MockEncodingMemory;

    impl EncodingMemory<Binary> for MockEncodingMemory {
        fn get_encodings(&self, values: &[Vector<U8>]) -> Vec<u8> {
            let ranges: Vec<Range<usize>> = values.iter().map(|r| r.to_raw().to_range()).collect();
            let ranges: RangeSet<usize> = ranges.into();

            generate_encodings(ranges)
        }
    }

    fn generate_encodings(index: RangeSet<usize>) -> Vec<u8> {
        let mut out = Vec::new();
        for el in index.iter() {
            out.extend_from_slice(&[el as u8; ENCODING_SIZE]);
        }
        out
    }
}
