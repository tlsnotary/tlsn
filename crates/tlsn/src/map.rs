use std::ops::Range;

use mpz_memory_core::{Vector, binary::U8};
use rangeset::RangeSet;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RangeMap<T> {
    map: Vec<(usize, T)>,
}

impl<T> Default for RangeMap<T>
where
    T: Item,
{
    fn default() -> Self {
        Self { map: Vec::new() }
    }
}

impl<T> RangeMap<T>
where
    T: Item,
{
    pub(crate) fn new(map: Vec<(usize, T)>) -> Self {
        let mut pos = 0;
        for (idx, item) in &map {
            assert!(
                *idx >= pos,
                "items must be sorted by index and non-overlapping"
            );

            pos = *idx + item.length();
        }

        Self { map }
    }

    /// Returns the keys of the map.
    pub(crate) fn keys(&self) -> impl Iterator<Item = Range<usize>> {
        self.map
            .iter()
            .map(|(idx, item)| *idx..*idx + item.length())
    }

    /// Returns the length of the map.
    pub(crate) fn len(&self) -> usize {
        self.map.iter().map(|(_, item)| item.length()).sum()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (Range<usize>, &T)> {
        self.map
            .iter()
            .map(|(idx, item)| (*idx..*idx + item.length(), item))
    }

    pub(crate) fn get(&self, range: Range<usize>) -> Option<T::Slice<'_>> {
        if range.start >= range.end {
            return None;
        }

        // Find the item with the greatest start index <= range.start
        let pos = match self.map.binary_search_by(|(idx, _)| idx.cmp(&range.start)) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };

        let (base, item) = &self.map[pos];

        item.slice(range.start - *base..range.end - *base)
    }

    pub(crate) fn index(&self, idx: &RangeSet<usize>) -> Option<Self> {
        let mut map = Vec::new();
        for idx in idx.iter_ranges() {
            let pos = match self.map.binary_search_by(|(base, _)| base.cmp(&idx.start)) {
                Ok(i) => i,
                Err(0) => return None,
                Err(i) => i - 1,
            };

            let (base, item) = self.map.get(pos)?;
            if idx.start < *base || idx.end > *base + item.length() {
                return None;
            }

            let start = idx.start - *base;
            let end = start + idx.len();

            map.push((
                idx.start,
                item.slice(start..end)
                    .expect("slice length is checked")
                    .into(),
            ));
        }

        Some(Self { map })
    }
}

impl<T> FromIterator<(usize, T)> for RangeMap<T>
where
    T: Item,
{
    fn from_iter<I: IntoIterator<Item = (usize, T)>>(items: I) -> Self {
        let mut pos = 0;
        let mut map = Vec::new();
        for (idx, item) in items {
            assert!(
                idx >= pos,
                "items must be sorted by index and non-overlapping"
            );

            pos = idx + item.length();
            map.push((idx, item));
        }

        Self { map }
    }
}

pub(crate) trait Item: Sized {
    type Slice<'a>: Into<Self>
    where
        Self: 'a;

    fn length(&self) -> usize;

    fn slice<'a>(&'a self, range: Range<usize>) -> Option<Self::Slice<'a>>;
}

impl Item for Vector<U8> {
    type Slice<'a> = Vector<U8>;

    fn length(&self) -> usize {
        self.len()
    }

    fn slice<'a>(&'a self, range: Range<usize>) -> Option<Self::Slice<'a>> {
        self.get(range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Item for Range<usize> {
        type Slice<'a> = Range<usize>;

        fn length(&self) -> usize {
            self.end - self.start
        }

        fn slice(&self, range: Range<usize>) -> Option<Self> {
            if range.end > self.end - self.start {
                return None;
            }

            Some(range.start + self.start..range.end + self.start)
        }
    }

    #[test]
    fn test_range_map() {
        let map = RangeMap::from_iter([(0, 10..14), (10, 20..24), (20, 30..32)]);

        assert_eq!(map.get(0..4), Some(10..14));
        assert_eq!(map.get(10..14), Some(20..24));
        assert_eq!(map.get(20..22), Some(30..32));
        assert_eq!(map.get(0..2), Some(10..12));
        assert_eq!(map.get(11..13), Some(21..23));
        assert_eq!(map.get(0..10), None);
        assert_eq!(map.get(10..20), None);
        assert_eq!(map.get(20..30), None);
    }

    #[test]
    fn test_range_map_index() {
        let map = RangeMap::from_iter([(0, 10..14), (10, 20..24), (20, 30..32)]);

        let idx = RangeSet::from([0..4, 10..14, 20..22]);
        assert_eq!(map.index(&idx), Some(map.clone()));

        let idx = RangeSet::from(25..30);
        assert_eq!(map.index(&idx), None);

        let idx = RangeSet::from(15..20);
        assert_eq!(map.index(&idx), None);

        let idx = RangeSet::from([1..3, 11..12, 13..14, 21..22]);
        assert_eq!(
            map.index(&idx),
            Some(RangeMap::from_iter([
                (1, 11..13),
                (11, 21..22),
                (13, 23..24),
                (21, 31..32)
            ]))
        );
    }
}
