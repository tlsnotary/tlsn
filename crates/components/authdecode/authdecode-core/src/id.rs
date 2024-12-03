/// A unique identifier.
#[derive(Default, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Id(pub u64);

/// A trait for working with a collection of ids.
///
/// It is permissible for the collection to contain duplicate ids.
#[allow(clippy::len_without_is_empty)]
pub trait IdCollection: PartialEq + Default + Clone {
    /// Drains and returns `count` ids from the front of the collection, modifying the collection.
    /// If the length of the collection is less than `count`, drains the entire collection.
    ///
    /// # Panics
    ///
    /// Panics if the `count` is invalid.
    ///
    /// # Arguments
    ///
    /// * `count` - The amount of ids to drain.
    fn drain_front(&mut self, count: usize) -> Self;

    /// Returns the id of an elements at the given `index` in the collection.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of an id.
    ///
    /// # Panics
    ///
    /// Panics if there is no id with the given index in the collection.
    fn id(&self, index: usize) -> Id;

    /// Returns the amount of ids in the collection.
    fn len(&self) -> usize;

    /// Whether the collection is empty.
    fn is_empty(&self) -> bool;

    /// Constructs a collection from an iterator over collections.
    ///
    /// # Panics
    ///
    /// Panics if a collection cannot be constructed.
    fn new_from_iter<I: IntoIterator<Item = Self>>(iter: I) -> Self;
}
