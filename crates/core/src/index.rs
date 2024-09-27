use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::{Field, FieldId},
    transcript::{
        hash::{PlaintextHash, PlaintextHashSecret},
        Idx,
    },
};

/// Index for items which can be looked up by transcript index or field id.
#[derive(Debug, Clone)]
pub(crate) struct Index<T> {
    items: Vec<T>,
    // Lookup by field id
    field_ids: HashMap<FieldId, usize>,
    // Lookup by transcript index
    transcript_idxs: HashMap<Idx, usize>,
}

impl<T> Default for Index<T> {
    fn default() -> Self {
        Self {
            items: Default::default(),
            field_ids: Default::default(),
            transcript_idxs: Default::default(),
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
        F: Fn(&T) -> (&FieldId, &Idx),
    {
        let mut field_ids = HashMap::new();
        let mut transcript_idxs = HashMap::new();
        for (i, item) in items.iter().enumerate() {
            let (id, idx) = f(item);
            field_ids.insert(*id, i);
            transcript_idxs.insert(idx.clone(), i);
        }
        Self {
            items,
            field_ids,
            transcript_idxs,
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    pub(crate) fn get_by_field_id(&self, id: &FieldId) -> Option<&T> {
        self.field_ids.get(id).map(|i| &self.items[*i])
    }

    pub(crate) fn get_by_transcript_idx(&self, idx: &Idx) -> Option<&T> {
        self.transcript_idxs.get(idx).map(|i| &self.items[*i])
    }
}

impl From<Vec<Field<PlaintextHash>>> for Index<Field<PlaintextHash>> {
    fn from(items: Vec<Field<PlaintextHash>>) -> Self {
        Self::new(items, |field: &Field<PlaintextHash>| {
            (&field.id, &field.data.idx)
        })
    }
}

impl From<Vec<PlaintextHashSecret>> for Index<PlaintextHashSecret> {
    fn from(items: Vec<PlaintextHashSecret>) -> Self {
        Self::new(items, |item: &PlaintextHashSecret| {
            (&item.commitment, &item.idx)
        })
    }
}

#[cfg(test)]
mod test {
    use utils::range::RangeSet;

    use super::*;

    #[derive(PartialEq, Debug, Clone)]
    struct Stub {
        field_index: FieldId,
        index: Idx,
    }

    impl From<Vec<Stub>> for Index<Stub> {
        fn from(items: Vec<Stub>) -> Self {
            Self::new(items, |item: &Stub| (&item.field_index, &item.index))
        }
    }

    fn stubs() -> Vec<Stub> {
        vec![
            Stub {
                field_index: FieldId(1),
                index: Idx::new(RangeSet::from([0..1, 18..21])),
            },
            Stub {
                field_index: FieldId(2),
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
                index: stub_a_index.clone(),
            },
            Stub {
                field_index: stub_b_field_index,
                index: Idx::new(RangeSet::from([1..5, 8..11])),
            },
        ];
        let stubs_index: Index<Stub> = stubs.clone().into();

        assert_eq!(
            stubs_index.get_by_field_id(&stub_b_field_index),
            Some(&stubs[1])
        );
        assert_eq!(
            stubs_index.get_by_transcript_idx(&stub_a_index),
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
        assert_eq!(stubs_index.get_by_transcript_idx(&wrong_index), None);
    }
}
