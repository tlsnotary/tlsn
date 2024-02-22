use crate::{backend::traits::Field, bitid::IdSet};

use super::{state, state::EncodingState, Encoding};

/// A non-empty collection of active encodings with the associated plaintext value.
#[derive(Clone, PartialEq, Debug)]
pub struct ActiveEncodings<T: IdSet, S: EncodingState = state::Original> {
    pub encodings: Vec<Encoding<S>>,
    /// The id of each bit of the encoded plaintext.
    pub ids: T,
    state: S,
}

impl<T> ActiveEncodings<T, state::Original>
where
    T: IdSet,
{
    /// Creates a new collection of active encodings.
    ///
    /// # Panics
    ///
    /// Panics if the source is empty. Panics if more than one encoding encodes the same bit.
    pub fn new(encodings: Vec<Encoding>, ids: T) -> Self {
        assert!(!encodings.is_empty());
        // TODO check that all encoding ids are unique

        Self {
            encodings,
            ids,
            state: state::Original {},
        }
    }

    /// Converts the encodings ... TODO
    ///
    /// Panics
    pub fn convert(&self) -> ActiveEncodings<T, state::Converted> {
        ActiveEncodings {
            encodings: self
                .encodings
                .iter()
                .map(|enc| enc.convert())
                .collect::<Vec<_>>(),
            ids: self.ids.clone(),
            state: state::Converted {},
        }
    }
}

impl<T, S> ActiveEncodings<T, S>
where
    S: EncodingState + Default,
    T: IdSet,
{
    /// Creates a new collection from an iterator.
    pub fn new_from_iter<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        let (encodings, ids): (Vec<_>, Vec<_>) =
            iter.into_iter().map(|e| (e.encodings, e.ids)).unzip();

        Self {
            encodings: encodings.into_iter().flatten().collect(),
            state: S::default(),
            ids: T::new_from_iter(ids),
        }
    }

    /// Returns an iterator ... TODO
    pub fn into_chunks(self, chunk_size: usize) -> ActiveEncodingsChunks<T, S> {
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

    /// Returns plaintext bits encoded by this collection.
    pub fn plaintext(&self) -> Vec<bool> {
        self.encodings.iter().map(|enc| enc.bit).collect::<Vec<_>>()
    }

    /// Returns the id of each bit of plaintext encoded by this collection.
    pub fn ids(&self) -> &T {
        &self.ids
    }
}

impl<T> ActiveEncodings<T, state::Converted>
where
    T: IdSet,
{
    /// Computes the arithmetic sum of the encodings.
    pub fn compute_sum<F>(&self) -> F
    where
        F: Field + std::ops::Add<Output = F>,
    {
        self.encodings.iter().fold(F::zero(), |acc, x| -> F {
            acc + F::from_bytes_be(x.value().to_vec())
        })
    }
}

pub struct ActiveEncodingsChunks<T, S: EncodingState> {
    chunk_size: usize,
    encodings: <Vec<Encoding<S>> as IntoIterator>::IntoIter,
    ids: T,
}

impl<T, S> Iterator for ActiveEncodingsChunks<T, S>
where
    S: EncodingState + Default,
    T: IdSet,
{
    type Item = ActiveEncodings<T, S>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.encodings.len() == 0 {
            None
        } else {
            Some(ActiveEncodings {
                // TODO does this modify the collection as it should?
                encodings: self
                    .encodings
                    .by_ref()
                    .take(self.chunk_size)
                    .collect::<Vec<_>>(),
                ids: self.ids.drain_front(self.chunk_size),
                state: S::default(),
            })
        }
    }
}
