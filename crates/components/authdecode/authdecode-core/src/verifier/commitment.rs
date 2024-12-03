use crate::{backend::traits::Field, id::IdCollection};

use getset::Getters;

/// A yet-unverified commitment to plaintext of an arbitrary length and related details.
#[derive(Clone, Getters)]
pub struct UnverifiedCommitment<I, F> {
    /// A non-empty collection of commitment details for each chunk of the plaintext.
    #[getset(get = "pub")]
    chunk_commitments: Vec<UnverifiedChunkCommitment<I, F>>,
}

impl<I, F> UnverifiedCommitment<I, F>
where
    I: IdCollection + Default,
    F: Field,
{
    /// Creates a new `UnverifiedCommitment` instance.
    ///
    /// # Arguments
    ///
    /// * `chunk_commitments` - A non-empty collection of commitment details for each chunk of the
    ///                         plaintext.
    pub fn new(chunk_commitments: Vec<UnverifiedChunkCommitment<I, F>>) -> Self {
        Self { chunk_commitments }
    }

    /// Returns the id of each bit of the plaintext of this commitment.
    pub fn ids(&self) -> I {
        let iter = self
            .chunk_commitments
            .iter()
            .map(|com| com.ids.clone())
            .collect::<Vec<_>>();

        I::new_from_iter(iter)
    }

    /// Returns the length of the plaintext of this commitment.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.chunk_commitments.iter().map(|com| com.ids.len()).sum()
    }
}

/// A yet-unverified commitment details for a single chunk of plaintext.
#[derive(Clone, Getters)]
pub struct UnverifiedChunkCommitment<I, F> {
    /// Hash commitment to the plaintext.
    #[getset(get = "pub")]
    plaintext_hash: F,
    /// Hash commitment to the arithemtic sum of the encodings of the plaintext.
    #[getset(get = "pub")]
    encoding_sum_hash: F,
    /// The id of each bit of the committed plaintext in LSB0 bit order.
    #[getset(get = "pub")]
    ids: I,
}

impl<I, F> UnverifiedChunkCommitment<I, F>
where
    I: IdCollection,
    F: Field,
{
    /// Creates a new unverified chunk commitment.
    ///
    /// # Arguments
    ///
    /// * `plaintext_hash` - Hash commitment to the plaintext.
    /// * `encoding_sum_hash` - Hash commitment to the arithemtic sum of the encodings of the plaintext.
    /// * `ids` - The id of each bit of the committed plaintext.
    pub fn new(plaintext_hash: F, encoding_sum_hash: F, ids: I) -> Self {
        Self {
            plaintext_hash,
            encoding_sum_hash,
            ids,
        }
    }

    /// Returns the bitlength of the plaintext committed to.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.ids.len()
    }
}

/// A verified commitment to plaintext of an arbitrary length.
#[derive(Clone)]
pub struct VerifiedCommitment<I, F> {
    /// A non-empty collection of commitments for each chunk of the plaintext.
    chunk_commitments: Vec<VerifiedChunkCommitment<I, F>>,
}

impl<I, F> VerifiedCommitment<I, F>
where
    I: IdCollection + Default,
    F: Field,
{
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `chunk_commitments` - A non-empty collection of commitment details for each chunk of the
    ///                         plaintext.
    pub fn new(chunk_commitments: Vec<VerifiedChunkCommitment<I, F>>) -> Self {
        Self { chunk_commitments }
    }

    /// Returns the length of the plaintext of this commitment.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.chunk_commitments.iter().map(|com| com.ids.len()).sum()
    }

    /// Returns a non-empty collection of commitments for each chunk of the plaintext.
    pub fn chunk_commitments(&self) -> &Vec<VerifiedChunkCommitment<I, F>> {
        &self.chunk_commitments
    }
}

/// A verified commitment for a single chunk of plaintext.
#[derive(Clone, Getters)]
pub struct VerifiedChunkCommitment<I, F> {
    /// Hash commitment to the plaintext.
    #[getset(get = "pub")]
    plaintext_hash: F,
    /// Hash commitment to the arithemtic sum of the encodings of the plaintext.
    #[getset(get = "pub")]
    encoding_sum_hash: F,
    /// The id of each bit of the plaintext.
    #[getset(get = "pub")]
    ids: I,
}

impl<I, F> VerifiedChunkCommitment<I, F>
where
    I: IdCollection,
    F: Field,
{
    /// Creates a new `ChunkCommitment` instance.
    ///
    /// # Arguments
    ///
    /// * `plaintext_hash` - Hash commitment to the plaintext.
    /// * `encoding_sum_hash` - Hash commitment to the arithemtic sum of the encodings of the plaintext.
    /// * `ids` - The id of each bit of the committed plaintext.
    pub fn new(plaintext_hash: F, encoding_sum_hash: F, ids: I) -> Self {
        Self {
            plaintext_hash,
            encoding_sum_hash,
            ids,
        }
    }

    /// Returns the bitlength of the plaintext committed to.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.ids.len()
    }
}

impl<I, F> From<UnverifiedCommitment<I, F>> for VerifiedCommitment<I, F>
where
    I: IdCollection,
    F: Field,
{
    fn from(unverified: UnverifiedCommitment<I, F>) -> Self {
        Self {
            chunk_commitments: unverified
                .chunk_commitments
                .into_iter()
                .map(|com| VerifiedChunkCommitment {
                    plaintext_hash: com.plaintext_hash,
                    encoding_sum_hash: com.encoding_sum_hash,
                    ids: com.ids,
                })
                .collect::<Vec<_>>(),
        }
    }
}
