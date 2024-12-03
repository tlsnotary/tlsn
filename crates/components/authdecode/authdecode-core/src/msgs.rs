//! Protocol messages and types contained therein.

use crate::{
    backend::traits::Field,
    id::IdCollection,
    prover::CommitmentDetails,
    verifier::{UnverifiedChunkCommitment, UnverifiedCommitment},
    Proof,
};

use enum_try_as_inner::EnumTryAsInner;
use serde::{Deserialize, Serialize};

/// A protocol message.
#[derive(Debug, Clone, Serialize, EnumTryAsInner, Deserialize)]
#[derive_err(Debug)]
#[allow(missing_docs)]
pub enum Message<T: IdCollection, F: Field> {
    Commit(Commit<T, F>),
    Proofs(Proofs),
}

impl<I, F> From<MessageError<I, F>> for std::io::Error
where
    I: IdCollection,
    F: Field,
{
    fn from(err: MessageError<I, F>) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
    }
}

/// A commitment message sent by the prover.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(try_from = "UncheckedCommit<I, F>")]
pub struct Commit<I, F>
where
    I: IdCollection,
    F: Field,
{
    /// A non-empty collection of commitments. Each element is a commitment to plaintext of an
    /// arbitrary length.
    commitments: Vec<Commitment<I, F>>,
}

impl<I, F> Commit<I, F>
where
    I: IdCollection,
    F: Field,
{
    /// Returns the total number of chunks across all commitments in the collection.
    pub fn chunk_count(&self) -> usize {
        self.commitments
            .iter()
            .map(|inner| inner.chunk_commitments.len())
            .sum()
    }

    /// Returns the total number of commitments in the collection.
    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }
}

/// A message with proofs sent by the prover.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(try_from = "UncheckedProofs")]
pub struct Proofs {
    pub proofs: Vec<Proof>,
}

impl<I, F> Commit<I, F>
where
    I: IdCollection,
    F: Field,
{
    /// Converts this message into a collection of unverified commitments which the verifier can
    /// work with.
    ///
    /// # Arguments
    /// * `max_size` - The expected maximum bytesize of a chunk of plaintext committed to.
    pub fn into_vec_commitment(
        self,
        max_size: usize,
    ) -> Result<Vec<UnverifiedCommitment<I, F>>, std::io::Error> {
        self.commitments
            .into_iter()
            .map(|com| {
                let chunk_com = com
                    .chunk_commitments
                    .into_iter()
                    .map(|chunk_com| {
                        if chunk_com.ids.len() > max_size * 8 {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "The length of ids is larger than the chunk size.",
                            ))
                        } else {
                            Ok(UnverifiedChunkCommitment::new(
                                chunk_com.plaintext_hash,
                                chunk_com.encoding_sum_hash,
                                chunk_com.ids,
                            ))
                        }
                    })
                    .collect::<Result<Vec<_>, std::io::Error>>()?;

                Ok(UnverifiedCommitment::new(chunk_com))
            })
            .collect::<Result<Vec<_>, std::io::Error>>()
    }
}

impl<I, F> From<Vec<CommitmentDetails<I, F>>> for Commit<I, F>
where
    I: IdCollection,
    F: Field + Clone,
{
    fn from(source: Vec<CommitmentDetails<I, F>>) -> Commit<I, F> {
        Commit {
            commitments: source
                .into_iter()
                .map(|com| {
                    let chunk_commitments = com
                        .chunk_commitments()
                        .iter()
                        .map(|chunk_com| ChunkCommitment {
                            plaintext_hash: chunk_com.plaintext_hash().clone(),
                            encoding_sum_hash: chunk_com.encoding_sum_hash().clone(),
                            ids: chunk_com.ids().clone(),
                        })
                        .collect::<Vec<_>>();
                    Commitment { chunk_commitments }
                })
                .collect::<Vec<_>>(),
        }
    }
}

/// A single commitment to plaintext of an arbitrary length.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Commitment<I, F>
where
    I: IdCollection,
    F: Field,
{
    /// A non-empty collection of commitments to each chunk of the plaintext.
    chunk_commitments: Vec<ChunkCommitment<I, F>>,
}

/// A commitment to a single chunk of plaintext.
#[derive(Clone, Serialize, Deserialize, Debug)]
struct ChunkCommitment<I, F>
where
    I: IdCollection,
    F: Field,
{
    /// Hash commitment to the plaintext.
    plaintext_hash: F,
    /// Hash commitment to the `encoding_sum`.
    encoding_sum_hash: F,
    /// The id of each bit of the plaintext.
    ids: I,
}

/// A [`Commit`] message in its unchecked state.
#[derive(Deserialize)]
pub struct UncheckedCommit<I, F>
where
    I: IdCollection,
    F: Field,
{
    commitments: Vec<Commitment<I, F>>,
}

impl<I, F> TryFrom<UncheckedCommit<I, F>> for Commit<I, F>
where
    I: IdCollection,
    F: Field,
{
    type Error = std::io::Error;

    fn try_from(value: UncheckedCommit<I, F>) -> Result<Self, Self::Error> {
        // None of the commitment vectors should be empty.
        if value.commitments.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "empty commitment vector",
            ));
        }

        for com in &value.commitments {
            if com.chunk_commitments.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "empty chunk commitment vector",
                ));
            }
        }

        Ok(Commit {
            commitments: value.commitments,
        })
    }
}

#[derive(Deserialize)]
/// A [`Proof`] message in its unchecked state.
pub struct UncheckedProofs {
    proofs: Vec<Proof>,
}

impl TryFrom<UncheckedProofs> for Proofs {
    type Error = std::io::Error;

    fn try_from(value: UncheckedProofs) -> Result<Self, Self::Error> {
        if value.proofs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "empty proof vector",
            ));
        }

        Ok(Proofs {
            proofs: value.proofs,
        })
    }
}
