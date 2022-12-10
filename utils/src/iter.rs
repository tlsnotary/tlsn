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

#[inline]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    assert!(bv.len() & 7 == 0);
    let mut v = vec![0u8; bv.len() / 8];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (7 - (i % 8));
    }
    v
}

#[inline]
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}

pub fn boolvec_to_string(v: &[bool]) -> String {
    v.iter().map(|b| (*b as u8).to_string()).collect::<String>()
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
        assert!(x.iter().contains_dups_by(|x| x.get()));
    }

    #[test]
    fn test_boolvec_to_u8vec() {
        let mut u = vec![false; 16];
        u[7] = true;
        assert_eq!(boolvec_to_u8vec(&u), &256u16.to_be_bytes());

        let v = (0..128)
            .map(|_| rand::random::<bool>())
            .collect::<Vec<bool>>();
        let v_ = boolvec_to_u8vec(&v);
        let v__ = u8vec_to_boolvec(&v_);
        assert_eq!(v, v__);
    }

    #[test]
    fn test_u8vec_to_boolvec() {
        let mut u = vec![false; 16];
        u[7] = true;
        assert_eq!(u8vec_to_boolvec(&256u16.to_be_bytes()), u);

        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = u8vec_to_boolvec(&v);
        let v__ = boolvec_to_u8vec(&v_);
        assert_eq!(v, v__);
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
