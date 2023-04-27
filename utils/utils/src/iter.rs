use std::{collections::HashSet, hash::Hash};

/// XORs 2 slices of bytes of equal length
///
/// Panics if slices are not equal length
#[inline]
pub fn xor(a: &[u8], b: &[u8], out: &mut [u8]) {
    assert!(a.len() == b.len() && a.len() == out.len());
    for ((a, b), out) in a.iter().zip(b.iter()).zip(out.iter_mut()) {
        *out = a ^ b;
    }
}

/// Unzips a slice of pairs, returning items corresponding to choice
///
/// Panics if slices are not equal length
#[inline]
pub fn choose<T: Copy>(items: &[[T; 2]], choice: &[bool]) -> Vec<T> {
    assert!(items.len() == choice.len(), "arrays are different length");
    items
        .iter()
        .zip(choice)
        .map(|(items, choice)| items[*choice as usize])
        .collect()
}

/// Returns a subset of items in a collection which corresponds to provided indices
///
/// Panics if index is out of bounds
#[inline]
pub fn pick<T: Copy>(items: &[T], idx: &[usize]) -> Vec<T> {
    idx.iter().map(|i| items[*i]).collect()
}

/// This trait provides a helper method to determine whether an Iterator contains any duplicates.
pub trait DuplicateCheck<'a, T>
where
    Self: Iterator<Item = &'a T>,
    T: 'a + Hash + Eq + Clone,
{
    /// Checks iterator for any duplicates
    #[inline]
    fn contains_dups(&mut self) -> bool {
        let mut set = HashSet::<T>::default();
        for item in self {
            if set.contains(item) {
                return true;
            } else {
                set.insert(item.clone());
            }
        }
        false
    }
}

impl<'a, T, U> DuplicateCheck<'a, U> for T
where
    T: Iterator<Item = &'a U>,
    U: 'a + Hash + Eq + Clone,
{
}

/// This trait provides a helper method to determine whether an Iterator contains any duplicates
/// using an accessor function.
pub trait DuplicateCheckBy<'a, F, T, U>
where
    Self: Iterator<Item = &'a T>,
    F: Fn(&'a T) -> &'a U,
    T: 'a,
    U: 'a + Hash + Eq + Clone,
{
    /// Checks iterator for any duplicates using an accessor function
    #[inline]
    fn contains_dups_by(&mut self, f: F) -> bool {
        let mut set = HashSet::<U>::default();
        for item in self {
            if set.contains(f(item)) {
                return true;
            } else {
                set.insert(f(item).clone());
            }
        }
        false
    }
}

impl<'a, F, T, U, V> DuplicateCheckBy<'a, F, U, V> for T
where
    T: Iterator<Item = &'a U>,
    F: Fn(&'a U) -> &'a V,
    U: 'a,
    V: 'a + Hash + Eq + Clone,
{
}

pub struct FilterDrainIter<'a, F, T> {
    vec: &'a mut Vec<T>,
    pos: usize,
    pred: F,
}

impl<'a, F, T> Iterator for FilterDrainIter<'a, F, T>
where
    F: Fn(&T) -> bool,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.vec.len() {
            return None;
        }

        if (self.pred)(&self.vec[self.pos]) {
            return Some(self.vec.swap_remove(self.pos));
        } else {
            self.pos += 1;
            return self.next();
        }
    }
}

/// Helper trait that implements `drain_filter` which is not stable yet.
///
/// See [tracking issue](https://github.com/rust-lang/rust/issues/43244)
///
/// We call this `FilterDrain` to avoid the naming conflict with the standard library.
///
/// # Note
///
/// The order of the elements is not preserved.
pub trait FilterDrain<'a, F, T>
where
    F: Fn(&T) -> bool,
{
    type Item;
    type Iter: Iterator<Item = Self::Item> + 'a;

    fn filter_drain(&'a mut self, pred: F) -> Self::Iter;
}

impl<'a, F, T> FilterDrain<'a, F, T> for Vec<T>
where
    F: Fn(&T) -> bool + 'a,
    T: 'a,
{
    type Item = T;
    type Iter = FilterDrainIter<'a, F, T>;

    fn filter_drain(&'a mut self, pred: F) -> FilterDrainIter<'a, F, T> {
        FilterDrainIter {
            vec: self,
            pos: 0,
            pred,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct Container<T>(T);

    impl<T> Container<T> {
        fn get<'a>(&'a self) -> &'a T {
            &self.0
        }
    }

    #[test]
    fn test_filter_drain() {
        let mut v = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut even = v.filter_drain(|x| *x % 2 == 0).collect::<Vec<_>>();

        v.sort();
        even.sort();

        assert_eq!(even, vec![2, 4, 6, 8]);
        assert_eq!(v, vec![1, 3, 5, 7]);
    }

    #[test]
    fn duplicate_check_contains_dups() {
        let x = [0, 1, 1];
        assert!(x.iter().contains_dups());
    }

    #[test]
    fn duplicate_check_contains_no_dups() {
        let x = [0, 1];
        assert!(!x.iter().contains_dups());
    }

    #[test]
    fn duplicate_check_contains_dups_by() {
        let x = [Container(0), Container(1), Container(1)];
        assert!(x.iter().contains_dups_by(|x| x.get()));
    }

    #[test]
    fn duplicate_check_contains_no_dups_by() {
        let x = [Container(0), Container(1)];
        assert!(!x.iter().contains_dups_by(|x| x.get()));
    }

    #[test]
    fn test_xor() {
        let a = [2u8; 32];
        let b = [3u8; 32];
        let mut out = [0u8; 32];
        xor(&a, &b, &mut out);
        let expected = [1u8; 32];
        assert_eq!(out, expected);
    }

    #[should_panic]
    #[test]
    fn test_xor_panic() {
        let a = [2u8; 32];
        let b = [3u8; 31];
        let mut out = [0u8; 32];
        xor(&a, &b, &mut out);
    }
}
