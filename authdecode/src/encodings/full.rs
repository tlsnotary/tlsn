use crate::bitid::IdSet;

use super::{state, state::EncodingState, Encoding};
use crate::backend::traits::Field;

/// A non-empty collection of full encodings. Each item in the collection is the encodings of the 0
/// and 1 values of a bit.
#[derive(Clone, PartialEq, Default)]
pub struct FullEncodings<T: IdSet, S: EncodingState = state::Original> {
    pub encodings: Vec<[Encoding<S>; 2]>,
    /// The state of each encoding in this collection.
    pub ids: T,
    state: S,
}

impl<T, S> FullEncodings<T, S>
where
    S: EncodingState + Default,
    T: IdSet,
{
    /// Returns the number of full encodings.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.encodings.len()
    }

    /// Returns an iterator ... TODO
    pub fn into_chunks(self, chunk_size: usize) -> FullEncodingsChunks<T, S> {
        FullEncodingsChunks {
            chunk_size,
            encodings: self.encodings.into_iter(),
            ids: self.ids,
        }
    }

    /// Drains `count` encodings from the front.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains less than `count` encodings.
    pub fn drain_front(&mut self, count: usize) -> Self {
        let drained = self.encodings.drain(0..count).collect::<Vec<_>>();
        assert!(drained.len() == count);

        Self {
            encodings: drained,
            state: S::default(),
            ids: self.ids.drain_front(count),
        }
    }

    /// Computes the arithmetic sum of the 0 bit encodings.
    pub fn compute_zero_sum<F>(&self) -> F
    where
        F: Field + std::ops::Add<Output = F>,
    {
        self.encodings.iter().fold(F::zero(), |acc, x| {
            acc + F::from_bytes_be(x[0].value().to_vec())
        })
    }

    /// Computes the arithmetic difference between each pair of encodings.
    pub fn compute_deltas<F>(&self) -> Vec<F>
    where
        F: Field + std::ops::Sub<Output = F>,
    {
        self.encodings
            .iter()
            .map(|pair| {
                let a = F::from_bytes_be(pair[1].value().to_vec());
                let b = F::from_bytes_be(pair[0].value().to_vec());
                a - b
            })
            .collect()
    }

    /// Returns the ids of the plaintext bits which these full encodings are expected to encode.
    pub fn ids(&self) -> T {
        self.ids.clone()
    }
}

impl<T> FullEncodings<T, state::Original>
where
    T: IdSet,
{
    /// Creates a new collection of full encodings from a big-endian byte representation
    /// of each encoding.
    ///
    /// # Panics
    ///
    /// Panics if the source is empty or if any pair of encodings is invalid.
    pub fn new_from_bytes(encodings: Vec<[Vec<u8>; 2]>, ids: T) -> Self {
        assert!(!encodings.is_empty());

        let encodings = encodings
            .into_iter()
            .map(|enc| {
                [
                    Encoding::new(enc[0].clone(), false),
                    Encoding::new(enc[1].clone(), true),
                ]
            })
            .collect::<Vec<_>>();

        Self {
            encodings,
            state: state::Original {},
            ids,
        }
    }

    pub fn new(encodings: Vec<[Encoding; 2]>, ids: T) -> Self {
        assert!(!encodings.is_empty());

        for pair in encodings.clone() {
            assert!(!pair[0].bit && pair[1].bit);
        }

        Self {
            encodings,
            state: state::Original {},
            ids,
        }
    }

    /// Converts all encodings in the collection.
    pub fn convert(self) -> FullEncodings<T, state::Converted> {
        let converted = self
            .encodings
            .iter()
            .map(|pair| [pair[0].convert(), pair[1].convert()])
            .collect::<Vec<_>>();

        FullEncodings {
            encodings: converted,
            state: state::Converted {},
            ids: self.ids,
        }
    }
}

pub struct FullEncodingsChunks<T, S: EncodingState> {
    chunk_size: usize,
    encodings: <Vec<[Encoding<S>; 2]> as IntoIterator>::IntoIter,
    ids: T,
}

impl<T, S> Iterator for FullEncodingsChunks<T, S>
where
    S: EncodingState + Default,
    T: IdSet,
{
    type Item = FullEncodings<T, S>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.encodings.len() == 0 {
            None
        } else {
            Some(FullEncodings {
                // TODO is this correct? does this drain the original vector
                encodings: self
                    .encodings
                    .by_ref()
                    .take(self.chunk_size)
                    .collect::<Vec<_>>(),
                state: S::default(),
                ids: self.ids.drain_front(self.chunk_size),
            })
        }
    }
}
