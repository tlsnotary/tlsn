use crate::{
    backend::traits::Field,
    bitid::{Id, IdSet},
    encodings::{state::Converted, FullEncodings},
};

/// A commitment and related details for plaintext of an arbitrary length. The commitment has not been verified.
#[derive(Clone)]
pub struct UnverifiedCommitment<T, F>
where
    T: IdSet,
    F: Field,
{
    /// A non-empty collection of commitment details for each chunk of the plaintext.
    pub chunk_commitments: Vec<UnverifiedChunkCommitment<T, F>>,
}

impl<T, F> UnverifiedCommitment<T, F>
where
    T: IdSet + Default,
    F: Field,
{
    /// Creates a new `UnverifiedCommitment` instance.
    pub fn new(chunk_commitments: Vec<UnverifiedChunkCommitment<T, F>>) -> Self {
        Self { chunk_commitments }
    }
    /// Returns the id of each bit of the plaintext of this commitment.
    pub fn ids(&self) -> T {
        let iter = self
            .chunk_commitments
            .iter()
            .map(|com| com.ids.clone())
            .collect::<Vec<_>>();

        T::new_from_iter(iter)
    }

    /// Returns the length of the plaintext of this commitment.
    pub fn len(&self) -> usize {
        self.chunk_commitments.iter().map(|com| com.ids.len()).sum()
    }

    /// Sets full encodings for the plaintext of this commitment.
    ///
    /// # Panics
    ///
    /// Panics in any the following cases:
    /// - if the length of the full encodings does not match the length of the plaintext
    /// - if the full encodings are meant to encode plaintext bits with incorrect ids
    /// - if the full encodings have already been set
    pub fn set_full_encodings(&mut self, mut full_encodings: FullEncodings<T, Converted>) {
        assert!(self.len() == full_encodings.len());
        for com in self.chunk_commitments.iter_mut() {
            com.set_full_encodings(full_encodings.drain_front(com.len()))
        }
    }
}

/// Commitment details for a single chunk of plaintext. The commitment has not been verified.
#[derive(Clone)]
pub struct UnverifiedChunkCommitment<T, F>
where
    T: IdSet,
    F: Field,
{
    /// Hash commitment to the plaintext.
    pub plaintext_hash: F,
    /// Hash commitment to the arithemtic sum of the encodings of the plaintext.
    pub encoding_sum_hash: F,
    /// The id of each bit of the plaintext.
    pub ids: T,
    /// Full encodings of the plaintext bits in a converted state.
    pub full_encodings: Option<FullEncodings<T, Converted>>,
}

impl<T, F> UnverifiedChunkCommitment<T, F>
where
    T: IdSet,
    F: Field,
{
    /// Creates a new `ChunkCommitment` instance.
    pub fn new(
        plaintext_hash: F,
        encoding_sum_hash: F,
        ids: T,
        full_encodings: Option<FullEncodings<T, Converted>>,
    ) -> Self {
        Self {
            plaintext_hash,
            encoding_sum_hash,
            ids,
            full_encodings,
        }
    }

    /// Returns the bitlength of the plaintext committed to.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Sets full encodings for the plaintext of this commitment.
    ///
    /// # Panics
    ///
    /// Panics in any of the following cases:
    /// - if the full encodings have already been set
    /// - if the full encodings are meant to encode plaintext bits with incorrect ids
    pub fn set_full_encodings(&mut self, full_encodings: FullEncodings<T, Converted>) {
        assert!(self.full_encodings.is_none());
        assert!(self.ids == full_encodings.ids());
        self.full_encodings = Some(full_encodings);
    }
}

/// A verified commitment for plaintext of an arbitrary length.
#[derive(Clone)]
pub struct VerifiedCommitment<T, F> {
    /// A non-empty collection of commitments for each chunk of the plaintext.
    pub chunk_commitments: Vec<VerifiedChunkCommitment<T, F>>,
}

impl<T, F> VerifiedCommitment<T, F>
where
    T: IdSet + Default,
    F: Field,
{
    /// Creates a new `Commitment` instance.
    pub fn new(chunk_commitments: Vec<VerifiedChunkCommitment<T, F>>) -> Self {
        Self { chunk_commitments }
    }

    /// Returns the id of each bit of the plaintext of this commitment.
    pub fn ids(&self) -> T {
        T::default()
    }

    /// Returns the length of the plaintext of this commitment.
    pub fn len(&self) -> usize {
        self.chunk_commitments.iter().map(|com| com.ids.len()).sum()
    }
}

/// A verified commitment for single chunk of plaintext.
#[derive(Clone)]
pub struct VerifiedChunkCommitment<T, F> {
    /// Hash commitment to the plaintext.
    pub plaintext_hash: F,
    /// Hash commitment to the arithemtic sum of the encodings of the plaintext.
    pub encoding_sum_hash: F,
    /// The id of each bit of the plaintext.
    ids: T,
}

impl<T, F> VerifiedChunkCommitment<T, F>
where
    T: IdSet,
    F: Field,
{
    /// Creates a new `ChunkCommitment` instance.
    pub fn new(plaintext_hash: F, encoding_sum_hash: F, ids: T) -> Self {
        Self {
            plaintext_hash,
            encoding_sum_hash,
            ids,
        }
    }

    /// Returns the bitlength of the plaintext committed to.
    pub fn len(&self) -> usize {
        self.ids.len()
    }
}

impl<T, F> From<UnverifiedCommitment<T, F>> for VerifiedCommitment<T, F>
where
    T: IdSet,
    F: Field,
{
    fn from(unverified: UnverifiedCommitment<T, F>) -> Self {
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
