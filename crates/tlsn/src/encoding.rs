//! Encoding commitment protocol.

use std::ops::Range;

use mpz_common::Context;
use mpz_memory_core::{
    Vector,
    binary::U8,
    correlated::{Delta, Key, Mac},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serio::{SinkExt, stream::IoStreamExt};
use tlsn_core::{
    hash::HashAlgorithm,
    transcript::{
        Direction, Idx,
        encoding::{
            Encoder, EncoderSecret, EncodingCommitment, EncodingProvider, EncodingProviderError,
            EncodingTree, EncodingTreeError, new_encoder,
        },
    },
};

use crate::commit::transcript::TranscriptRefs;

/// Bytes of encoding, per byte.
const ENCODING_SIZE: usize = 128;

#[derive(Debug, Serialize, Deserialize)]
struct Encodings {
    sent: Vec<u8>,
    recv: Vec<u8>,
}

/// Transfers the encodings using the provided seed and keys.
///
/// The keys must be consistent with the global delta used in the encodings.
pub(crate) async fn transfer<'a>(
    ctx: &mut Context,
    refs: &TranscriptRefs,
    delta: &Delta,
    f: impl Fn(Vector<U8>) -> &'a [Key],
) -> Result<EncodingCommitment, EncodingError> {
    let secret = EncoderSecret::new(rand::rng().random(), delta.as_block().to_bytes());
    let encoder = new_encoder(&secret);

    let sent_keys: Vec<u8> = refs
        .sent()
        .iter()
        .copied()
        .flat_map(&f)
        .flat_map(|key| key.as_block().as_bytes())
        .copied()
        .collect();
    let recv_keys: Vec<u8> = refs
        .recv()
        .iter()
        .copied()
        .flat_map(&f)
        .flat_map(|key| key.as_block().as_bytes())
        .copied()
        .collect();

    assert_eq!(sent_keys.len() % ENCODING_SIZE, 0);
    assert_eq!(recv_keys.len() % ENCODING_SIZE, 0);

    let mut sent_encoding = Vec::with_capacity(sent_keys.len());
    let mut recv_encoding = Vec::with_capacity(recv_keys.len());

    encoder.encode_range(
        Direction::Sent,
        0..sent_keys.len() / ENCODING_SIZE,
        &mut sent_encoding,
    );
    encoder.encode_range(
        Direction::Received,
        0..recv_keys.len() / ENCODING_SIZE,
        &mut recv_encoding,
    );

    sent_encoding
        .iter_mut()
        .zip(sent_keys)
        .for_each(|(enc, key)| *enc ^= key);
    recv_encoding
        .iter_mut()
        .zip(recv_keys)
        .for_each(|(enc, key)| *enc ^= key);

    ctx.io_mut()
        .send(Encodings {
            sent: sent_encoding,
            recv: recv_encoding,
        })
        .await?;

    let root = ctx.io_mut().expect_next().await?;
    ctx.io_mut().send(secret.clone()).await?;

    Ok(EncodingCommitment {
        root,
        secret: secret.clone(),
    })
}

/// Receives the encodings using the provided MACs.
///
/// The MACs must be consistent with the global delta used in the encodings.
pub(crate) async fn receive<'a>(
    ctx: &mut Context,
    hasher: &(dyn HashAlgorithm + Send + Sync),
    refs: &TranscriptRefs,
    f: impl Fn(Vector<U8>) -> &'a [Mac],
    idxs: impl IntoIterator<Item = &(Direction, Idx)>,
) -> Result<(EncodingCommitment, EncodingTree), EncodingError> {
    let Encodings { mut sent, mut recv } = ctx.io_mut().expect_next().await?;

    let sent_macs: Vec<u8> = refs
        .sent()
        .iter()
        .copied()
        .flat_map(&f)
        .flat_map(|mac| mac.as_bytes())
        .copied()
        .collect();
    let recv_macs: Vec<u8> = refs
        .recv()
        .iter()
        .copied()
        .flat_map(&f)
        .flat_map(|mac| mac.as_bytes())
        .copied()
        .collect();

    assert_eq!(sent_macs.len() % ENCODING_SIZE, 0);
    assert_eq!(recv_macs.len() % ENCODING_SIZE, 0);

    if sent.len() != sent_macs.len() {
        return Err(ErrorRepr::IncorrectMacCount {
            direction: Direction::Sent,
            expected: sent_macs.len(),
            got: sent.len(),
        }
        .into());
    }

    if recv.len() != recv_macs.len() {
        return Err(ErrorRepr::IncorrectMacCount {
            direction: Direction::Received,
            expected: recv_macs.len(),
            got: recv.len(),
        }
        .into());
    }

    sent.iter_mut()
        .zip(sent_macs)
        .for_each(|(enc, mac)| *enc ^= mac);
    recv.iter_mut()
        .zip(recv_macs)
        .for_each(|(enc, mac)| *enc ^= mac);

    let provider = Provider { sent, recv };

    let tree = EncodingTree::new(hasher, idxs, &provider)?;
    let root = tree.root();

    ctx.io_mut().send(root.clone()).await?;
    let secret = ctx.io_mut().expect_next().await?;

    let commitment = EncodingCommitment { root, secret };

    Ok((commitment, tree))
}

#[derive(Debug)]
struct Provider {
    sent: Vec<u8>,
    recv: Vec<u8>,
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

        let start = range.start * ENCODING_SIZE;
        let end = range.end * ENCODING_SIZE;

        if end > encodings.len() {
            return Err(EncodingProviderError);
        }

        dest.extend_from_slice(&encodings[start..end]);

        Ok(())
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
