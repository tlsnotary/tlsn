use crate::{
    backend::traits::{Field, ProverBackend as Backend},
    bitid::IdSet,
    encodings::{active::ActiveEncodingsChunks, ActiveEncodings, Encoding},
    utils::{boolvec_to_u8vec, u8vec_to_boolvec},
    SSP,
};
use num::{BigInt, BigUint, FromPrimitive};

use super::error::ProverError;

/// The plaintext and the encodings which the prover commits to.
pub struct CommitmentData<T>
where
    T: IdSet,
{
    pub encodings: ActiveEncodings<T>,
}

impl<T> CommitmentData<T>
where
    T: IdSet,
{
    /// Creates a commitment to this data.
    pub fn commit<F>(
        &self,
        backend: &Box<dyn Backend<F>>,
    ) -> Result<CommitmentDetails<T, F>, ProverError>
    where
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        // Chunk up the data and commit to each chunk individually.
        let chunk_commitments = self
            .into_chunks(backend.chunk_size() * 8)
            .map(|data_chunk| data_chunk.commit(backend))
            .collect::<Result<Vec<ChunkCommitmentDetails<T, F>>, ProverError>>()?;

        Ok(CommitmentDetails { chunk_commitments })
    }

    /// Creates a new `CommitmentData` type for `plaintext` with the given bit ids. Bits encode to
    /// `encodings`.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext being committed to.
    /// * `encodings` - Uniformly random encodings of every bit of the `plaintext`.
    ///                 Note that correlated encodings like those used in e.g. garbled circuits must  
    ///                 not be used.
    /// * `bit_ids` - The id of each bit of the `plaintext`.
    ///
    /// # Panics
    ///
    /// Panics if `plaintext`, `encodings` and `bit_ids` are not all of the same length.
    pub fn new(plaintext: Vec<u8>, encodings: Vec<[u8; SSP / 8]>, bit_ids: T) -> CommitmentData<T> {
        assert!(plaintext.len() * 8 == encodings.len());
        assert!(plaintext.len() * 8 == bit_ids.len());

        let encodings = u8vec_to_boolvec(&plaintext)
            .iter()
            .zip(encodings)
            .map(|(bit, enc)| Encoding::new(enc, *bit))
            .collect::<Vec<_>>();

        CommitmentData {
            encodings: ActiveEncodings::new(encodings, bit_ids),
        }
    }

    pub fn into_chunks(&self, chunk_size: usize) -> CommitmentDataChunks<T> {
        CommitmentDataChunks {
            encodings: self.encodings.clone().into_chunks(chunk_size),
        }
    }
}

pub struct CommitmentDataChunks<T> {
    encodings: ActiveEncodingsChunks<T>,
}

impl<T> Iterator for CommitmentDataChunks<T>
where
    T: IdSet,
{
    type Item = CommitmentDataChunk<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.encodings
            .next()
            .map(|encodings| Some(CommitmentDataChunk { encodings }))?
    }
}

// A chunk of data that needs to be committed to.
pub struct CommitmentDataChunk<T>
where
    T: IdSet,
{
    pub encodings: ActiveEncodings<T>,
}

impl<T> CommitmentDataChunk<T>
where
    T: IdSet,
{
    /// Creates a commitment to this chunk.
    fn commit<F>(
        &self,
        backend: &Box<dyn Backend<F>>,
    ) -> Result<ChunkCommitmentDetails<T, F>, ProverError>
    where
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        // Convert the encodings and compute their sum.
        let sum = self.encodings.compute_sum::<F>();

        let (plaintext_hash, plaintext_salt) =
            backend.commit_plaintext(boolvec_to_u8vec(&self.encodings.plaintext()))?;

        let (encoding_sum_hash, encoding_sum_salt) = backend.commit_encoding_sum(sum.clone())?;

        Ok(ChunkCommitmentDetails {
            plaintext_hash,
            plaintext_salt,
            encodings: self.encodings.clone(),
            encoding_sum: sum,
            encoding_sum_hash,
            encoding_sum_salt,
        })
    }
}

/// An AuthDecode commitment to a single chunk of the plaintext with the associated details.
#[derive(Clone)]
pub struct ChunkCommitmentDetails<T, F>
where
    T: IdSet,
    F: Field,
{
    pub plaintext_hash: F,
    pub plaintext_salt: F,

    /// The encodings the sum of which is committed to.
    pub encodings: ActiveEncodings<T>,

    pub encoding_sum: F,
    pub encoding_sum_hash: F,
    pub encoding_sum_salt: F,
}

impl<T, F> ChunkCommitmentDetails<T, F>
where
    T: IdSet,
    F: Field,
{
    /// Returns the id of each bit of the plaintext.
    pub fn ids(&self) -> &T {
        self.encodings.ids()
    }
}

/// An AuthDecode commitment to plaintext of arbitrary length with the associated details.
#[derive(Clone, Default)]
pub struct CommitmentDetails<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
    /// Commitments to each chunk of the plaintext with the associated details.
    ///
    /// Internally, for performance reasons, the data to be committed to is split up into chunks
    /// and each chunk is committed to separately. The collection of chunk commitments constitutes
    /// the commitment.
    pub chunk_commitments: Vec<ChunkCommitmentDetails<T, F>>,
}

impl<T, F> CommitmentDetails<T, F>
where
    T: IdSet + Clone,
    F: Field + Clone,
{
    /// Returns the encodings of the plaintext of this commitment.
    pub fn encodings(&self) -> ActiveEncodings<T> {
        let iter = self
            .chunk_commitments
            .iter()
            .map(|enc| enc.encodings.clone());
        ActiveEncodings::new_from_iter(iter)
    }
}
