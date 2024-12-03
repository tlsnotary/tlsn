use crate::{backend::traits::Field, encodings::Encoding, id::IdCollection};

use getset::Getters;

/// A non-empty collection of full encodings. Each item in the collection is the encodings of the 0
/// and 1 values of a bit.
#[derive(Clone, PartialEq, Default, Debug, Getters)]
pub struct FullEncodings<I> {
    /// Full encodings for each bit.
    encodings: Vec<[Encoding; 2]>,
    /// The id of each bit encoded by the encodings of this collection.
    ///
    /// This type will not enforce that when there are duplicate ids in the collection, the values of
    /// the corresponding encodings must match.
    #[getset(get = "pub")]
    ids: I,
}

impl<I> FullEncodings<I>
where
    I: IdCollection,
{
    /// Creates a new collection of full encodings.
    ///
    /// # Arguments
    ///
    /// * `encodings` - The pairs of encodings.
    /// * `ids` - The collection of ids of each bit of the encoded plaintext.
    ///
    /// # Panics
    ///
    /// Panics if either `encodings` or `ids` is empty.
    pub fn new(encodings: Vec<[Encoding; 2]>, ids: I) -> Self {
        assert!(!encodings.is_empty() && !ids.is_empty());

        for pair in encodings.clone() {
            assert!(!pair[0].bit() && *pair[1].bit());
        }

        Self { encodings, ids }
    }

    /// Returns the number of full encodings.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.encodings.len()
    }

    /// Convert `self` into an iterator over chunks of the collection. If `chunk_size` does not divide
    /// the length of the collection, then the last chunk will not have length `chunk_size`.
    ///
    /// # Arguments
    ///
    /// * `chunk_size` - The size of a chunk.
    pub fn into_chunks(self, chunk_size: usize) -> FullEncodingsChunks<I> {
        FullEncodingsChunks {
            chunk_size,
            encodings: self.encodings.into_iter(),
            ids: self.ids,
        }
    }

    /// Drains `count` encodings from the front of the collection.
    ///
    /// # Arguments
    ///
    /// * `count` - The amount of encodings to drain.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains less than `count` encodings.
    pub fn drain_front(&mut self, count: usize) -> Self {
        let drained = self.encodings.drain(0..count).collect::<Vec<_>>();
        assert!(drained.len() == count);

        Self {
            encodings: drained,
            ids: self.ids.drain_front(count),
        }
    }

    /// Computes the arithmetic sum of the encodings of the bit value 0.
    pub fn compute_zero_sum<F>(&self) -> F
    where
        F: Field + std::ops::Add<Output = F>,
    {
        self.encodings
            .iter()
            .fold(F::zero(), |acc, x| acc + F::from_bytes(x[0].value()))
    }

    /// Computes the arithmetic difference between the encoding of the bit value 1 and the encoding
    /// of the bit value 0 for each pair in the collection.
    pub fn compute_deltas<F>(&self) -> Vec<F>
    where
        F: Field + std::ops::Sub<Output = F>,
    {
        self.encodings
            .iter()
            .map(|pair| {
                let a = F::from_bytes(pair[1].value());
                let b = F::from_bytes(pair[0].value());
                a - b
            })
            .collect()
    }

    #[cfg(any(test, feature = "mock"))]
    /// Returns full encodings for each bit.
    pub fn encodings(&self) -> &[[Encoding; 2]] {
        &self.encodings
    }
}

pub struct FullEncodingsChunks<I> {
    chunk_size: usize,
    encodings: <Vec<[Encoding; 2]> as IntoIterator>::IntoIter,
    ids: I,
}

impl<I> Iterator for FullEncodingsChunks<I>
where
    I: IdCollection,
{
    type Item = FullEncodings<I>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.encodings.len() == 0 {
            None
        } else {
            Some(FullEncodings {
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
        encodings::{Encoding, FullEncodings},
        mock::{Direction, MockBitIds},
    };

    // Tests that chunking of full encodings works correctly.
    #[allow(clippy::single_range_in_vec_init)]
    #[test]
    fn test_full_encodings_chunks() {
        const BYTE_COUNT: usize = 22;
        const CHUNK_BYTESIZE: usize = 14;

        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let all_encodings = (0..BYTE_COUNT * 8)
            .map(|_| {
                let mut pair = [Encoding::random(&mut rng); 2];
                // Set the correct bit values.
                pair[0].set_bit(false);
                pair[1].set_bit(true);
                pair
            })
            .collect::<Vec<_>>();

        let ids = MockBitIds::new(Direction::Sent, &[0..BYTE_COUNT]);
        let full = FullEncodings::new(all_encodings.clone(), ids);

        let mut chunk_iter = full.into_chunks(CHUNK_BYTESIZE * 8);

        // The first chunk will contain encodings for `CHUNK_BYTESIZE` bytes.
        let expected_chunk1_encodings = FullEncodings::new(
            all_encodings[0..CHUNK_BYTESIZE * 8].to_vec(),
            MockBitIds::new(Direction::Sent, &[0..CHUNK_BYTESIZE]),
        );

        // The second chunk will contain encodings for `BYTE_COUNT - CHUNK_BYTESIZE` bytes.
        let expected_chunk2_encodings = FullEncodings::new(
            all_encodings[CHUNK_BYTESIZE * 8..BYTE_COUNT * 8].to_vec(),
            MockBitIds::new(Direction::Sent, &[CHUNK_BYTESIZE..BYTE_COUNT]),
        );

        assert_eq!(chunk_iter.next().unwrap(), expected_chunk1_encodings);
        assert_eq!(chunk_iter.next().unwrap(), expected_chunk2_encodings);
    }
}
