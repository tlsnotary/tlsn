/// A unique identifier.
#[derive(Default, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Id(pub u64);

/// A trait for working with a collection of ids.
#[allow(clippy::len_without_is_empty)]
pub trait IdSet: PartialEq + Default + Clone {
    /// Drains `count` ids (or the whole collection) from the front of the collection
    /// returning the drained ids.
    ///
    fn drain_front(&mut self, count: usize) -> Self;

    /// Returns the id of an elements at the given `index`.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds of this collection.
    fn id(&self, index: usize) -> Id;

    /// Returns all ids in the collection.
    fn ids(&self) -> Vec<Id>;

    ///
    fn len(&self) -> usize;

    /// Constructs a set from an iterator over sets.
    ///
    /// # Panics
    ///
    /// Panics if a set cannot be constructed.
    fn new_from_iter<I: IntoIterator<Item = Self>>(iter: I) -> Self;
}
