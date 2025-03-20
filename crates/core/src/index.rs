use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::{Field, FieldId},
    transcript::{
        hash::{PlaintextHash, PlaintextHashSecret},
        Direction, Idx,
    },
};

/// Index for items which can be looked up by transcript's (direction and index)
/// or field id.
#[derive(Debug, Clone)]
pub(crate) struct Index<T> {
    items: Vec<T>,
    // Lookup by field id.
    field_ids: HashMap<FieldId, usize>,
    // Lookup by transcript direction and index.
    transcript_idxs: HashMap<(Direction, Idx), usize>,
    /// Union of all sent indices.
    sent: Idx,
    /// Union of all received indices.
    recv: Idx,
}

impl<T> Default for Index<T> {
    fn default() -> Self {
        Self {
            items: Default::default(),
            field_ids: Default::default(),
            transcript_idxs: Default::default(),
            sent: Default::default(),
            recv: Default::default(),
        }
    }
}

impl<T: Serialize> Serialize for Index<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.items.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Index<T>
where
    Index<T>: From<Vec<T>>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Vec::<T>::deserialize(deserializer).map(Index::from)
    }
}

impl<T> From<Index<T>> for Vec<T> {
    fn from(value: Index<T>) -> Self {
        value.items
    }
}

impl<T> Index<T> {
    pub(crate) fn new<F>(items: Vec<T>, f: F) -> Self
    where
        F: Fn(&T) -> (&FieldId, Direction, &Idx),
    {
        let mut field_ids = HashMap::new();
        let mut transcript_idxs = HashMap::new();
        let mut sent = Idx::default();
        let mut recv = Idx::default();
        for (i, item) in items.iter().enumerate() {
            let (id, dir, idx) = f(item);
            field_ids.insert(*id, i);
            transcript_idxs.insert((dir, idx.clone()), i);
            match dir {
                Direction::Sent => sent.union_mut(idx),
                Direction::Received => recv.union_mut(idx),
            }
        }

        Self {
            items,
            field_ids,
            transcript_idxs,
            sent,
            recv,
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    pub(crate) fn get_by_field_id(&self, id: &FieldId) -> Option<&T> {
        self.field_ids.get(id).map(|i| &self.items[*i])
    }

    #[allow(unused)]
    pub(crate) fn get_by_transcript_idx(&self, dir_idx: &(Direction, Idx)) -> Option<&T> {
        self.transcript_idxs.get(dir_idx).map(|i| &self.items[*i])
    }

    pub(crate) fn idx(&self, direction: Direction) -> &Idx {
        match direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.recv,
        }
    }

    #[allow(unused)]
    pub(crate) fn iter_idxs(&self) -> impl Iterator<Item = &(Direction, Idx)> {
        self.transcript_idxs.keys()
    }
}

impl From<Vec<Field<PlaintextHash>>> for Index<Field<PlaintextHash>> {
    fn from(items: Vec<Field<PlaintextHash>>) -> Self {
        Self::new(items, |field: &Field<PlaintextHash>| {
            (&field.id, field.data.direction, &field.data.idx)
        })
    }
}

impl From<Vec<PlaintextHashSecret>> for Index<PlaintextHashSecret> {
    fn from(items: Vec<PlaintextHashSecret>) -> Self {
        Self::new(items, |item: &PlaintextHashSecret| {
            (&item.commitment, item.direction, &item.idx)
        })
    }
}

#[cfg(test)]
mod test {
    use rangeset::RangeSet;

    use super::*;

    #[derive(PartialEq, Debug, Clone)]
    struct Stub {
        field_index: FieldId,
        direction: Direction,
        index: Idx,
    }

    impl From<Vec<Stub>> for Index<Stub> {
        fn from(items: Vec<Stub>) -> Self {
            Self::new(items, |item: &Stub| {
                (&item.field_index, item.direction, &item.index)
            })
        }
    }

    fn stubs() -> Vec<Stub> {
        vec![
            Stub {
                field_index: FieldId(1),
                direction: Direction::Sent,
                index: Idx::new(RangeSet::from([0..1, 18..21])),
            },
            Stub {
                field_index: FieldId(2),
                direction: Direction::Received,
                index: Idx::new(RangeSet::from([1..5, 8..11])),
            },
        ]
    }

    #[test]
    fn test_successful_retrieval() {
        let stub_a_index = Idx::new(RangeSet::from([0..4, 7..10]));
        let stub_b_field_index = FieldId(8);

        let stubs = vec![
            Stub {
                field_index: FieldId(1),
                direction: Direction::Sent,
                index: stub_a_index.clone(),
            },
            Stub {
                field_index: stub_b_field_index,
                direction: Direction::Received,
                index: Idx::new(RangeSet::from([1..5, 8..11])),
            },
        ];
        let stubs_index: Index<Stub> = stubs.clone().into();

        assert_eq!(
            stubs_index.get_by_field_id(&stub_b_field_index),
            Some(&stubs[1])
        );
        assert_eq!(
            stubs_index.get_by_transcript_idx(&(Direction::Sent, stub_a_index)),
            Some(&stubs[0])
        );
    }

    #[test]
    fn test_failed_retrieval() {
        let stubs = stubs();
        let stubs_index: Index<Stub> = stubs.clone().into();

        let wrong_index = Idx::new(RangeSet::from([0..3, 4..5]));
        let wrong_field_index = FieldId(200);

        assert_eq!(stubs_index.get_by_field_id(&wrong_field_index), None);
        assert_eq!(
            stubs_index.get_by_transcript_idx(&(Direction::Sent, wrong_index)),
            None
        );
    }
}
