use crate::{backend::traits::Field, encodings::Encoding, id::IdCollection};

use getset::Getters;
use itybity::FromBitIterator;

/// A non-empty collection of active bit encodings with the associated plaintext value.
#[derive(Clone, PartialEq, Debug, Getters, Default)]
pub struct ActiveEncodings<I> {
    /// The encoding for each bit of the plaintext in LSB0 bit order.
    #[getset(get = "pub")]
    encodings: Vec<Encoding>,
    /// A collection of ids of each bit of the encoded plaintext.
    ///
    /// This type will not enforce that when there are duplicate ids in the collection, the values of
    /// the corresponding encodings must match.
    #[getset(get = "pub")]
    ids: I,
}

impl<I> ActiveEncodings<I>
where
    I: IdCollection,
{
    /// Creates a new collection of active encodings.
    ///
    /// # Arguments
    ///
    /// * `encodings` - The active encodings.
    /// * `ids` - The collection of ids of each bit of the encoded plaintext.
    ///
    /// # Panics
    ///
    /// Panics if either `encodings` or `ids` is empty.
    pub fn new(encodings: Vec<Encoding>, ids: I) -> Self {
        assert!(!encodings.is_empty() && !ids.is_empty());

        Self { encodings, ids }
    }

    /// Creates a new collection from an iterator.
    ///
    /// # Arguments
    ///
    /// * `iter` - The iterator from which to create the collection.
    pub fn new_from_iter<It: IntoIterator<Item = Self>>(iter: It) -> Self {
        let (encodings, ids): (Vec<_>, Vec<_>) =
            iter.into_iter().map(|e| (e.encodings, e.ids)).unzip();

        Self {
            encodings: encodings.into_iter().flatten().collect(),
            ids: I::new_from_iter(ids),
        }
    }

    /// Convert `self` into an iterator over chunks of the collection. If `chunk_size` does not divide
    /// the length of the collection, then the last chunk will not have length `chunk_size`.
    ///
    /// # Arguments
    ///
    /// * `chunk_size` - The size of a chunk.
    pub fn into_chunks(self, chunk_size: usize) -> ActiveEncodingsChunks<I> {
        ActiveEncodingsChunks {
            chunk_size,
            encodings: self.encodings.into_iter(),
            ids: self.ids,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    /// Returns the number of active encodings.
    pub fn len(&self) -> usize {
        self.encodings.len()
    }

    /// Returns the plaintext encoded by this collection.
    pub fn plaintext(&self) -> Vec<u8> {
        Vec::<u8>::from_lsb0_iter(self.encodings.iter().map(|enc| *enc.bit()))
    }
}

impl<I> ActiveEncodings<I>
where
    I: IdCollection,
{
    /// Computes the arithmetic sum of the encodings.
    pub fn compute_sum<F>(&self) -> F
    where
        F: Field + std::ops::Add<Output = F>,
    {
        self.encodings
            .iter()
            .fold(F::zero(), |acc, x| -> F { acc + F::from_bytes(x.value()) })
    }
}

pub struct ActiveEncodingsChunks<I> {
    chunk_size: usize,
    encodings: <Vec<Encoding> as IntoIterator>::IntoIter,
    ids: I,
}

impl<I> Iterator for ActiveEncodingsChunks<I>
where
    I: IdCollection,
{
    type Item = ActiveEncodings<I>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.encodings.len() == 0 {
            None
        } else {
            Some(ActiveEncodings {
                encodings: self
                    .encodings
                    .by_ref()
                    .take(self.chunk_size)
                    .collect::<Vec<_>>(),
                ids: self.ids.drain_front(self.chunk_size),
            })
        }
    }
}

#[cfg(test)]
mod tests {

    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use crate::{
        encodings::Encoding,
        mock::{Direction, MockBitIds},
    };

    use super::*;

    // Tests that chunking of active encodings works correctly.
    #[allow(clippy::single_range_in_vec_init)]
    #[test]
    fn test_active_encodings_chunks() {
        const BYTE_COUNT: usize = 22;
        const CHUNK_BYTESIZE: usize = 14;

        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let all_encodings = [Encoding::random(&mut rng); BYTE_COUNT * 8].to_vec();

        let ids = MockBitIds::new(Direction::Sent, &[0..BYTE_COUNT]);
        let active = ActiveEncodings::new(all_encodings.clone(), ids);

        let mut chunk_iter = active.into_chunks(CHUNK_BYTESIZE * 8);

        // The first chunk will contain encodings for `CHUNK_BYTESIZE` bytes.
        let expected_chunk1_encodings = ActiveEncodings::new(
            all_encodings[0..CHUNK_BYTESIZE * 8].to_vec(),
            MockBitIds::new(Direction::Sent, &[0..CHUNK_BYTESIZE]),
        );

        // The second chunk will contain encodings for `BYTE_COUNT - CHUNK_BYTESIZE` bytes.
        let expected_chunk2_encodings = ActiveEncodings::new(
            all_encodings[CHUNK_BYTESIZE * 8..BYTE_COUNT * 8].to_vec(),
            MockBitIds::new(Direction::Sent, &[CHUNK_BYTESIZE..BYTE_COUNT]),
        );

        assert_eq!(chunk_iter.next().unwrap(), expected_chunk1_encodings);
        assert_eq!(chunk_iter.next().unwrap(), expected_chunk2_encodings);
    }
}
