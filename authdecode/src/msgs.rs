//! Protocol messages.

use crate::{
    backend::traits::Field, bitid::IdSet, prover::commitment::CommitmentDetails, InitData, Proof,
};
use serde::{Deserialize, Serialize};

/// A commitment message sent by the prover.
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "UncheckedCommit<T, F>")]
pub struct Commit<T, F> {
    /// A non-empty collection of commitments. Each element is a commitment to plaintext of an
    /// arbitrary length.
    pub commitments: Vec<Commitment<T, F>>,
}

impl<T, F> Commit<T, F>
where
    T: IdSet,
    F: Field,
{
    /// Converts this message into a vector of `Commitment`s which the verifier can work with.
    ///
    /// # Arguments
    /// * `chunk_size` - The expected maximum bitsize of a chunk of plaintext committed to.
    pub fn into_vec_commitment(
        self,
        max_size: usize,
    ) -> Result<Vec<crate::verifier::commitment::UnverifiedCommitment<T, F>>, std::io::Error> {
        self.commitments
            .into_iter()
            .map(|com| {
                let chunk_com = com
                    .chunk_commitments
                    .into_iter()
                    .map(|chunk_com| {
                        if chunk_com.ids.len() > max_size {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "The length of ids is larger than the chunk size.",
                            ))
                        } else {
                            Ok(crate::verifier::commitment::UnverifiedChunkCommitment::new(
                                chunk_com.plaintext_hash,
                                chunk_com.encoding_sum_hash,
                                chunk_com.ids,
                                None,
                            ))
                        }
                    })
                    .collect::<Result<Vec<_>, std::io::Error>>()?;

                Ok(crate::verifier::commitment::UnverifiedCommitment::new(
                    chunk_com,
                ))
            })
            .collect::<Result<Vec<_>, std::io::Error>>()
    }
}

impl<T, F> From<Vec<CommitmentDetails<T, F>>> for Commit<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
    fn from(source: Vec<CommitmentDetails<T, F>>) -> Commit<T, F> {
        Commit {
            commitments: source
                .into_iter()
                .map(|com| {
                    let chunk_commitments = com
                        .chunk_commitments
                        .into_iter()
                        .map(|chunk_com| ChunkCommitment {
                            plaintext_hash: chunk_com.plaintext_hash.clone(),
                            encoding_sum_hash: chunk_com.encoding_sum_hash.clone(),
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
#[derive(Clone, Serialize, Deserialize)]
pub struct Commitment<T, F> {
    /// A non-empty collection of commitments to each chunk of the plaintext.
    chunk_commitments: Vec<ChunkCommitment<T, F>>,
}

/// A commitment to a single chunk of plaintext.
#[derive(Clone, Serialize, Deserialize)]
struct ChunkCommitment<T, F> {
    plaintext_hash: F,
    encoding_sum_hash: F,
    /// The id of each bit of the plaintext.
    ids: T,
}

/// Verification data sent by the verifier enabling the prover to check the authenticity of the
/// encodings committed to.
#[derive(Serialize, Deserialize)]
pub struct VerificationData {
    /// Data to initialize the encoding verifier with.
    pub init_data: InitData,
}

/// Proofs sent by the prover.
#[derive(Serialize, Deserialize)]
#[serde(try_from = "UncheckedProofs")]
pub struct Proofs {
    pub proofs: Vec<Proof>,
}

/// A commitment message sent by the prover.
#[derive(Deserialize)]
pub struct UncheckedCommit<T, F> {
    pub commitments: Vec<Commitment<T, F>>,
}

impl<T, F> TryFrom<UncheckedCommit<T, F>> for Commit<T, F> {
    type Error = std::io::Error;

    fn try_from(value: UncheckedCommit<T, F>) -> Result<Self, Self::Error> {
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
pub struct UncheckedProofs {
    pub proofs: Vec<Proof>,
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
