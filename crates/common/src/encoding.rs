//! Encoding commitment protocol.

use std::ops::Range;

use mpz_common::Context;
use mpz_core::Block;
use serde::{Deserialize, Serialize};
use serio::{stream::IoStreamExt, SinkExt};
use tlsn_core::transcript::{
    encoding::{new_encoder, Encoder, EncoderSecret, EncodingProvider, EncodingProviderError},
    Direction,
};

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
pub async fn transfer(
    ctx: &mut Context,
    secret: &EncoderSecret,
    sent_keys: impl IntoIterator<Item = &'_ Block>,
    recv_keys: impl IntoIterator<Item = &'_ Block>,
) -> Result<(), EncodingError> {
    let encoder = new_encoder(secret);

    let sent_keys: Vec<u8> = sent_keys
        .into_iter()
        .flat_map(|key| key.as_bytes())
        .copied()
        .collect();
    let recv_keys: Vec<u8> = recv_keys
        .into_iter()
        .flat_map(|key| key.as_bytes())
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

    Ok(())
}

/// Receives the encodings using the provided MACs.
///
/// The MACs must be consistent with the global delta used in the encodings.
pub async fn receive(
    ctx: &mut Context,
    sent_macs: impl IntoIterator<Item = &'_ Block>,
    recv_macs: impl IntoIterator<Item = &'_ Block>,
) -> Result<impl EncodingProvider, EncodingError> {
    let Encodings { mut sent, mut recv } = ctx.io_mut().expect_next().await?;

    let sent_macs: Vec<u8> = sent_macs
        .into_iter()
        .flat_map(|mac| mac.as_bytes())
        .copied()
        .collect();
    let recv_macs: Vec<u8> = recv_macs
        .into_iter()
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

    Ok(Provider { sent, recv })
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
}

impl From<std::io::Error> for EncodingError {
    fn from(value: std::io::Error) -> Self {
        Self(ErrorRepr::Io(value))
    }
}
