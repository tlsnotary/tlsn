//! Encoding commitment protocol.

use crate::commit::transcript::TranscriptRefs;
use mpz_memory_core::{
    Vector,
    binary::U8,
    correlated::{Delta, Key, Mac},
};
use rand::Rng;
use rangeset::{RangeSet, Subset};
use serde::{Deserialize, Serialize};
use std::ops::Range;
use tlsn_core::{
    hash::{Blake3, HashAlgId, HashAlgorithm, Keccak256, Sha256, TypedHash},
    transcript::{
        Direction, Idx,
        encoding::{
            Encoder, EncoderSecret, EncodingCommitment, EncodingProvider, EncodingProviderError,
            EncodingTree, EncodingTreeError, new_encoder,
        },
    },
};

/// Bytes of encoding, per byte.
const ENCODING_SIZE: usize = 128;

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
    root: Option<TypedHash>,
    tree: Option<EncodingTree>,
    secret: Option<EncoderSecret>,
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
        Self {
            id,
            sent,
            recv,
            root: None,
            tree: None,
            secret: None,
        }
    }

    /// Receives the encodings using the provided MACs.
    ///
    /// The MACs must be consistent with the global delta used in the encodings.
    ///
    /// # Arguments
    ///
    /// * `encodings` - The encoding adjustments.
    /// * `transcript_refs` - The transcript references.
    /// * `mac_provider` - Provides the mac encodings.
    pub(crate) fn receive<'a>(
        &mut self,
        encodings: Encodings,
        transcript_refs: &TranscriptRefs,
        mac_provider: impl Fn(Vector<U8>) -> &'a [Mac],
    ) -> Result<TypedHash, EncodingError> {
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

        let Encodings { mut sent, mut recv } = encodings;
        self.adjust(
            transcript_refs,
            |reference| {
                mac_provider(reference)
                    .iter()
                    .flat_map(|mac| mac.as_bytes())
            },
            &mut sent,
            &mut recv,
        )?;

        let provider = Provider::new(sent, &self.sent, recv, &self.recv);
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

        self.root = Some(root);
        self.tree = Some(tree);
        Ok(root)
    }

    /// Transfers the encodings using the provided seed and keys.
    ///
    /// The keys must be consistent with the global delta used in the encodings.
    ///
    /// # Arguments
    ///
    /// * `delta` -  The global delta.
    /// * `transcript_refs` - The transcript references.
    /// * `key_provider` - Provides the key blocks.
    pub(crate) fn transfer<'a>(
        &mut self,
        delta: &Delta,
        transcript_refs: &TranscriptRefs,
        key_provider: impl Fn(Vector<U8>) -> &'a [Key],
    ) -> Result<(Encodings, EncoderSecret), EncodingError> {
        let secret = EncoderSecret::new(rand::rng().random(), delta.as_block().to_bytes());
        let encoder = new_encoder(&secret);

        let mut sent = Vec::with_capacity(self.sent.len() * ENCODING_SIZE);
        let mut recv = Vec::with_capacity(self.recv.len() * ENCODING_SIZE);

        for range in self.sent.iter_ranges() {
            encoder.encode_range(Direction::Sent, range, &mut sent);
        }

        for range in self.recv.iter_ranges() {
            encoder.encode_range(Direction::Received, range, &mut recv);
        }

        self.adjust(
            transcript_refs,
            |reference| {
                key_provider(reference)
                    .iter()
                    .flat_map(|key| key.as_block().as_bytes())
            },
            &mut sent,
            &mut recv,
        )?;
        let encodings = Encodings { sent, recv };

        self.secret = Some(secret);
        Ok((encodings, secret))
    }

    /// Sets the encoder secret.
    ///
    /// # Arguments
    ///
    /// * `secret` - The encoder secret.
    pub(crate) fn set_secret(&mut self, secret: EncoderSecret) {
        self.secret = Some(secret);
    }

    /// Sets the encoding root.
    ///
    /// # Arguments
    ///
    /// * `root` - The encoder root.
    pub(crate) fn set_root(&mut self, root: TypedHash) {
        self.root = Some(root);
    }

    /// Returns the encoding commitment.
    pub(crate) fn commitment(&self) -> Option<EncodingCommitment> {
        let (Some(root), Some(secret)) = (self.root, self.secret) else {
            return None;
        };

        let commitment = EncodingCommitment { root, secret };
        Some(commitment)
    }

    /// Returns the encoding tree.
    pub(crate) fn tree(self) -> Option<EncodingTree> {
        self.tree
    }

    /// Adjust encodings by transcript references.
    ///
    /// # Arguments
    ///
    /// * `transcript_refs` - The transcripf references.
    /// * `provider` - The provider function for the transcript encodings.
    /// * `sent_adjust` - The adjustment bytes for the sent encodings.
    /// * `recv_adjust` - The adjustment bytes for the received encodings.
    fn adjust<'a, F, G>(
        &self,
        transcript_refs: &TranscriptRefs,
        provider: F,
        sent_adjust: &mut [u8],
        recv_adjust: &mut [u8],
    ) -> Result<(), EncodingError>
    where
        F: Fn(Vector<U8>) -> G,
        G: Iterator<Item = &'a u8>,
    {
        let sent: Vec<u8> = transcript_refs
            .get(Direction::Sent, &self.sent)
            .into_iter()
            .flat_map(&provider)
            .copied()
            .collect();
        let recv: Vec<u8> = transcript_refs
            .get(Direction::Received, &self.recv)
            .into_iter()
            .flat_map(&provider)
            .copied()
            .collect();

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

    use crate::commit::{
        encoding::{ENCODING_SIZE, EncodingCreator, Encodings, Provider},
        transcript::TranscriptRefs,
    };
    use mpz_memory_core::{FromRaw, Slice, Vector, binary::U8};
    use rangeset::{RangeSet, UnionMut};
    use rstest::{fixture, rstest};
    use tlsn_core::{
        hash::HashAlgId,
        transcript::{Direction, encoding::EncodingProvider},
    };

    #[rstest]
    fn test_encoding_adjust(
        index: (RangeSet<usize>, RangeSet<usize>),
        encodings: Encodings,
        transcript_refs: TranscriptRefs,
    ) {
        let (sent_range, recv_range) = index;
        let Encodings { mut sent, mut recv } = encodings;

        let mut sent_expected = Vec::new();
        let mut recv_expected = Vec::new();

        for el in sent.iter() {
            sent_expected.push(el ^ 1);
        }
        for el in recv.iter() {
            recv_expected.push(el ^ 1);
        }

        let creator = EncodingCreator::new(Some(HashAlgId::SHA256), sent_range, recv_range);
        let provider =
            |reference: Vector<U8>| std::iter::repeat_n(&1_u8, reference.len() * ENCODING_SIZE);

        creator
            .adjust(&transcript_refs, provider, &mut sent, &mut recv)
            .unwrap();

        assert_eq!(sent, sent_expected);
        assert_eq!(recv, recv_expected);
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

        let mut expected_sent = Vec::new();
        let mut expected_recv = Vec::new();

        generate_encodings((15..21).into(), &mut expected_sent);
        generate_encodings((50..56).into(), &mut expected_recv);

        assert_eq!(expected_sent, encodings_sent);
        assert_eq!(expected_recv, encodings_recv);
    }

    #[fixture]
    fn transcript_refs(index: (RangeSet<usize>, RangeSet<usize>)) -> TranscriptRefs {
        let mut transcript_refs = TranscriptRefs::new(1000, 1000);

        let dummy = |range: &Range<usize>| {
            Vector::<U8>::from_raw(Slice::from_range_unchecked(8 * range.start..8 * range.end))
        };

        for range in index.0.iter_ranges() {
            transcript_refs.add(Direction::Sent, &range, dummy(&range));
        }

        for range in index.1.iter_ranges() {
            transcript_refs.add(Direction::Received, &range, dummy(&range));
        }

        transcript_refs
    }

    #[fixture]
    fn encodings(index: (RangeSet<usize>, RangeSet<usize>)) -> Encodings {
        let mut sent = Vec::new();
        let mut recv = Vec::new();

        generate_encodings(index.0, &mut sent);
        generate_encodings(index.1, &mut recv);

        Encodings { sent, recv }
    }

    #[fixture]
    fn index() -> (RangeSet<usize>, RangeSet<usize>) {
        let mut sent = RangeSet::default();
        sent.union_mut(&(1..6));
        sent.union_mut(&(15..21));
        sent.union_mut(&(30..36));

        let mut recv = RangeSet::default();
        recv.union_mut(&(40..46));
        recv.union_mut(&(50..56));

        (sent, recv)
    }

    fn generate_encodings(index: RangeSet<usize>, out: &mut Vec<u8>) {
        for el in index.iter() {
            out.extend_from_slice(&[el as u8; ENCODING_SIZE]);
        }
    }
}
