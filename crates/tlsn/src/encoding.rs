//! Encoding commitment protocol.

use std::ops::Range;

use mpz_common::Context;
use mpz_memory_core::{
    Vector,
    binary::U8,
    correlated::{Delta, Key, Mac},
};
use rand::Rng;
use rangeset::RangeSet;
use serde::{Deserialize, Serialize};
use serio::{SinkExt, stream::IoStreamExt};
use tlsn_core::{
    hash::{Blake3, HashAlgId, HashAlgorithm, Keccak256, Sha256},
    transcript::{
        Direction,
        encoding::{
            Encoder, EncoderSecret, EncodingCommitment, EncodingProvider, EncodingProviderError,
            EncodingTree, EncodingTreeError, new_encoder,
        },
    },
};

use crate::commit::transcript::{Item, RangeMap, ReferenceMap};

/// Bytes of encoding, per byte.
const ENCODING_SIZE: usize = 128;

#[derive(Debug, Serialize, Deserialize)]
struct Encodings {
    sent: Vec<u8>,
    recv: Vec<u8>,
}

/// Transfers encodings for the provided plaintext ranges.
pub(crate) async fn transfer<K: KeyStore>(
    ctx: &mut Context,
    store: &K,
    sent: &ReferenceMap,
    recv: &ReferenceMap,
) -> Result<EncodingCommitment, EncodingError> {
    let secret = EncoderSecret::new(rand::rng().random(), store.delta().as_block().to_bytes());
    let encoder = new_encoder(&secret);

    // Collects the encodings for the provided plaintext ranges.
    fn collect_encodings(
        encoder: &impl Encoder,
        store: &impl KeyStore,
        direction: Direction,
        map: &ReferenceMap,
    ) -> Vec<u8> {
        let mut encodings = Vec::with_capacity(map.len() * ENCODING_SIZE);
        for (range, chunk) in map.iter() {
            let start = encodings.len();
            encoder.encode_range(direction, range, &mut encodings);
            let keys = store
                .get_keys(*chunk)
                .expect("keys are present for provided plaintext ranges");
            encodings[start..]
                .iter_mut()
                .zip(keys.iter().flat_map(|key| key.as_block().as_bytes()))
                .for_each(|(encoding, key)| {
                    *encoding ^= *key;
                });
        }
        encodings
    }

    let encodings = Encodings {
        sent: collect_encodings(&encoder, store, Direction::Sent, sent),
        recv: collect_encodings(&encoder, store, Direction::Received, recv),
    };

    let frame_limit = ctx.io().limit() + encodings.sent.len() + encodings.recv.len();
    ctx.io_mut().with_limit(frame_limit).send(encodings).await?;

    let root = ctx.io_mut().expect_next().await?;
    ctx.io_mut().send(secret.clone()).await?;

    Ok(EncodingCommitment { root, secret })
}

/// Receives and commits to the encodings for the provided plaintext ranges.
pub(crate) async fn receive<M: MacStore>(
    ctx: &mut Context,
    store: &M,
    hash_alg: HashAlgId,
    sent: &ReferenceMap,
    recv: &ReferenceMap,
    idxs: impl IntoIterator<Item = &(Direction, RangeSet<usize>)>,
) -> Result<(EncodingCommitment, EncodingTree), EncodingError> {
    let hasher: &(dyn HashAlgorithm + Send + Sync) = match hash_alg {
        HashAlgId::SHA256 => &Sha256::default(),
        HashAlgId::KECCAK256 => &Keccak256::default(),
        HashAlgId::BLAKE3 => &Blake3::default(),
        alg => {
            return Err(ErrorRepr::UnsupportedHashAlgorithm(alg).into());
        }
    };

    let (sent_len, recv_len) = (sent.len(), recv.len());
    let frame_limit = ctx.io().limit() + ENCODING_SIZE * (sent_len + recv_len);
    let encodings: Encodings = ctx.io_mut().with_limit(frame_limit).expect_next().await?;

    if encodings.sent.len() != sent_len * ENCODING_SIZE {
        return Err(ErrorRepr::IncorrectMacCount {
            direction: Direction::Sent,
            expected: sent_len,
            got: encodings.sent.len() / ENCODING_SIZE,
        }
        .into());
    }

    if encodings.recv.len() != recv_len * ENCODING_SIZE {
        return Err(ErrorRepr::IncorrectMacCount {
            direction: Direction::Received,
            expected: recv_len,
            got: encodings.recv.len() / ENCODING_SIZE,
        }
        .into());
    }

    // Collects a map of plaintext ranges to their encodings.
    fn collect_map(
        store: &impl MacStore,
        mut encodings: Vec<u8>,
        map: &ReferenceMap,
    ) -> RangeMap<EncodingSlice> {
        let mut encoding_map = Vec::new();
        let mut pos = 0;
        for (range, chunk) in map.iter() {
            let macs = store
                .get_macs(*chunk)
                .expect("MACs are present for provided plaintext ranges");
            let encoding = &mut encodings[pos..pos + range.len() * ENCODING_SIZE];
            encoding
                .iter_mut()
                .zip(macs.iter().flat_map(|mac| mac.as_bytes()))
                .for_each(|(encoding, mac)| {
                    *encoding ^= *mac;
                });

            encoding_map.push((range.start, EncodingSlice::from(&(*encoding))));
            pos += range.len() * ENCODING_SIZE;
        }
        RangeMap::new(encoding_map)
    }

    let provider = Provider {
        sent: collect_map(store, encodings.sent, sent),
        recv: collect_map(store, encodings.recv, recv),
    };

    let tree = EncodingTree::new(hasher, idxs, &provider)?;
    let root = tree.root();

    ctx.io_mut().send(root.clone()).await?;
    let secret = ctx.io_mut().expect_next().await?;

    let commitment = EncodingCommitment { root, secret };

    Ok((commitment, tree))
}

pub(crate) trait KeyStore {
    fn delta(&self) -> &Delta;

    fn get_keys(&self, data: Vector<U8>) -> Option<&[Key]>;
}

impl KeyStore for crate::verifier::Zk {
    fn delta(&self) -> &Delta {
        crate::verifier::Zk::delta(self)
    }

    fn get_keys(&self, data: Vector<U8>) -> Option<&[Key]> {
        self.get_keys(data).ok()
    }
}

pub(crate) trait MacStore {
    fn get_macs(&self, data: Vector<U8>) -> Option<&[Mac]>;
}

impl MacStore for crate::prover::Zk {
    fn get_macs(&self, data: Vector<U8>) -> Option<&[Mac]> {
        self.get_macs(data).ok()
    }
}

#[derive(Debug)]
struct Provider {
    sent: RangeMap<EncodingSlice>,
    recv: RangeMap<EncodingSlice>,
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

        let encoding = encodings.get(range).ok_or(EncodingProviderError)?;

        dest.extend_from_slice(encoding);

        Ok(())
    }
}

#[derive(Debug)]
struct EncodingSlice(Vec<u8>);

impl From<&[u8]> for EncodingSlice {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl Item for EncodingSlice {
    type Slice<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn length(&self) -> usize {
        self.0.len() / ENCODING_SIZE
    }

    fn slice<'a>(&'a self, range: Range<usize>) -> Option<Self::Slice<'a>> {
        self.0
            .get(range.start * ENCODING_SIZE..range.end * ENCODING_SIZE)
    }
}

/// Encoding protocol error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct EncodingError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("encoding protocol error: {0}")]
enum ErrorRepr {
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("incorrect MAC count for {direction}: expected {expected}, got {got}")]
    IncorrectMacCount {
        direction: Direction,
        expected: usize,
        got: usize,
    },
    #[error("encoding tree error: {0}")]
    EncodingTree(EncodingTreeError),
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(HashAlgId),
}

impl From<std::io::Error> for EncodingError {
    fn from(value: std::io::Error) -> Self {
        Self(ErrorRepr::Io(value))
    }
}

impl From<EncodingTreeError> for EncodingError {
    fn from(value: EncodingTreeError) -> Self {
        Self(ErrorRepr::EncodingTree(value))
    }
}
