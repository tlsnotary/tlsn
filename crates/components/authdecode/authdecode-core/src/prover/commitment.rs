use crate::{
    backend::traits::{Field, ProverBackend as Backend},
    encodings::{active::ActiveEncodingsChunks, ActiveEncodings, Encoding},
    id::IdCollection,
    prover::error::ProverError,
    SSP,
};

use getset::Getters;
use itybity::ToBits;

/// The plaintext and the encodings which the prover commits to.
#[derive(Clone, Default)]
pub struct CommitmentData<I>
where
    I: IdCollection,
{
    encodings: ActiveEncodings<I>,
}

impl<I> CommitmentData<I>
where
    I: IdCollection,
{
    /// Creates a commitment to this commitment data.
    #[allow(clippy::borrowed_box)]
    pub fn commit<F>(
        self,
        backend: &Box<dyn Backend<F>>,
    ) -> Result<CommitmentDetails<I, F>, ProverError>
    where
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        // Chunk up the data and commit to each chunk individually.
        let chunk_commitments = self
            .into_chunks(backend.chunk_size())
            .map(|data_chunk| data_chunk.commit(backend))
            .collect::<Vec<ChunkCommitmentDetails<I, F>>>();

        Ok(CommitmentDetails { chunk_commitments })
    }

    /// Creates a commitment to this commitment data with the provided `salts` for each
    /// chunk of the data.
    ///
    /// Returns an error if the amount of salts is not equal to the amount of chunks.
    #[allow(clippy::borrowed_box)]
    pub fn commit_with_salt<F>(
        self,
        backend: &Box<dyn Backend<F>>,
        salts: Vec<Vec<u8>>,
    ) -> Result<CommitmentDetails<I, F>, ProverError>
    where
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        // Chunk up the data.
        let chunks = self.into_chunks(backend.chunk_size()).collect::<Vec<_>>();

        if chunks.len() < salts.len() {
            return Err(ProverError::MismatchedSaltChunkCount);
        }

        let chunk_commitments = chunks
            .into_iter()
            .zip(salts)
            .map(|(chunk, salt)| chunk.commit_with_salt(backend, &salt))
            .collect::<Vec<ChunkCommitmentDetails<I, F>>>();

        Ok(CommitmentDetails { chunk_commitments })
    }

    /// Creates new commitment data.
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext being committed to.
    /// * `encodings` - Uniformly random encodings of every bit of the `plaintext` in LSB0 bit order.
    ///                 Note that correlated encodings like those used in garbled circuits must  
    ///                 not be used since they are not uniformly random.
    /// * `bit_ids` - The id of each bit of the `plaintext`.
    ///
    /// # Panics
    ///
    /// Panics if `plaintext`, `encodings` and `bit_ids` are not all of the same length.
    pub fn new(plaintext: &[u8], encodings: &[[u8; SSP / 8]], bit_ids: I) -> CommitmentData<I> {
        assert!(plaintext.len() * 8 == encodings.len());
        assert!(encodings.len() == bit_ids.len());

        let encodings = plaintext
            .to_lsb0_vec()
            .into_iter()
            .zip(encodings)
            .map(|(bit, enc)| Encoding::new(*enc, bit))
            .collect::<Vec<_>>();

        CommitmentData {
            encodings: ActiveEncodings::new(encodings, bit_ids),
        }
    }

    /// Convert `self` into an iterator over chunks of the commitment data. If `chunk_size` does not
    /// divide the length of the commitment data, then the last chunk will not have length `chunk_size`.
    ///
    /// # Arguments
    ///
    /// * `chunk_size` - The size of a chunk.
    pub fn into_chunks(self, chunk_size: usize) -> CommitmentDataChunks<I> {
        CommitmentDataChunks {
            encodings: self.encodings.clone().into_chunks(chunk_size * 8),
        }
    }
}

pub struct CommitmentDataChunks<I> {
    encodings: ActiveEncodingsChunks<I>,
}

impl<I> Iterator for CommitmentDataChunks<I>
where
    I: IdCollection,
{
    type Item = CommitmentDataChunk<I>;

    fn next(&mut self) -> Option<Self::Item> {
        self.encodings
            .next()
            .map(|encodings| Some(CommitmentDataChunk { encodings }))?
    }
}

/// A chunk of data that needs to be committed to.
pub struct CommitmentDataChunk<I>
where
    I: IdCollection,
{
    /// The active encoding of each bit of the plaintext. The number of encodings is always a
    /// multiple of 8.
    encodings: ActiveEncodings<I>,
}

impl<I> CommitmentDataChunk<I>
where
    I: IdCollection,
{
    /// Creates a commitment to this chunk.
    #[allow(clippy::borrowed_box)]
    fn commit<F>(&self, backend: &Box<dyn Backend<F>>) -> ChunkCommitmentDetails<I, F>
    where
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        let sum = self.encodings.compute_sum::<F>();

        let (plaintext_hash, plaintext_salt) =
            backend.commit_plaintext(&self.encodings.plaintext());

        let (encoding_sum_hash, encoding_sum_salt) = backend.commit_encoding_sum(sum.clone());

        ChunkCommitmentDetails {
            plaintext_hash,
            plaintext_salt,
            encodings: self.encodings.clone(),
            encoding_sum: sum,
            encoding_sum_hash,
            encoding_sum_salt,
        }
    }

    /// Creates a commitment to this chunk with the provided salt.
    #[allow(clippy::borrowed_box)]
    fn commit_with_salt<F>(
        &self,
        backend: &Box<dyn Backend<F>>,
        salt: &[u8],
    ) -> ChunkCommitmentDetails<I, F>
    where
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        let sum = self.encodings.compute_sum::<F>();

        let plaintext_hash = backend.commit_plaintext_with_salt(&self.encodings.plaintext(), salt);

        let (encoding_sum_hash, encoding_sum_salt) = backend.commit_encoding_sum(sum.clone());

        ChunkCommitmentDetails {
            plaintext_hash,
            plaintext_salt: F::from_bytes(salt),
            encodings: self.encodings.clone(),
            encoding_sum: sum,
            encoding_sum_hash,
            encoding_sum_salt,
        }
    }
}

/// An AuthDecode commitment to a single chunk of plaintext with the associated details.
#[derive(Clone, Getters)]
pub struct ChunkCommitmentDetails<I, F> {
    /// Hash commitment to the plaintext.
    #[getset(get = "pub")]
    plaintext_hash: F,
    /// The salt used to create the commitment to the plaintext.
    #[getset(get = "pub")]
    plaintext_salt: F,
    /// The encodings the sum of which is committed to.
    #[getset(get = "pub")]
    encodings: ActiveEncodings<I>,
    /// The sum of the encodings.
    #[getset(get = "pub")]
    encoding_sum: F,
    /// Hash commitment to the `encoding_sum`.
    #[getset(get = "pub")]
    encoding_sum_hash: F,
    /// The salt used to create the commitment to the `encoding_sum`.
    #[getset(get = "pub")]
    encoding_sum_salt: F,
}

impl<I, F> ChunkCommitmentDetails<I, F>
where
    I: IdCollection,
    F: Field,
{
    /// Returns the id of each bit of the plaintext.
    pub fn ids(&self) -> &I {
        self.encodings.ids()
    }
}

/// An AuthDecode commitment to plaintext of arbitrary length with the associated details.
#[derive(Clone, Default, Getters)]
pub struct CommitmentDetails<I, F> {
    /// Commitments to each chunk of the plaintext with the associated details.
    ///
    /// Internally, for performance reasons, the data to be committed to is split up into chunks
    /// and each chunk is committed to separately. The collection of chunk commitments constitutes
    /// the commitment.
    #[getset(get = "pub")]
    chunk_commitments: Vec<ChunkCommitmentDetails<I, F>>,
}

impl<I, F> CommitmentDetails<I, F>
where
    I: IdCollection + Clone,
    F: Field + Clone,
{
    /// Returns the encodings of the plaintext of this commitment.
    pub fn encodings(&self) -> ActiveEncodings<I> {
        let iter = self
            .chunk_commitments
            .iter()
            .map(|enc| enc.encodings.clone());
        ActiveEncodings::new_from_iter(iter)
    }
}
