use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::{Field, FieldId},
    transcript::{
        hash::{PlaintextHash, PlaintextHashSecret},
        Idx,
    },
};

/// Index for items which can be looked up by subsequence or field id.
#[derive(Debug, Clone)]
pub(crate) struct Index<T> {
    items: Vec<T>,
    // Index to lookup by field id
    ids: HashMap<FieldId, usize>,
    // Index to lookup by transcript index
    idxs: HashMap<Idx, usize>,
}

impl<T> Default for Index<T> {
    fn default() -> Self {
        Self {
            items: Default::default(),
            ids: Default::default(),
            idxs: Default::default(),
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
        let mut ids = HashMap::new();
        let mut idxs = HashMap::new();
        for (i, item) in items.iter().enumerate() {
            let (id, idx) = f(item);
            ids.insert(id.clone(), i);
            idxs.insert(idx.clone(), i);
        }
        Self { items, ids, idxs }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    pub(crate) fn get_by_id(&self, id: &FieldId) -> Option<&T> {
        self.ids.get(id).map(|i| &self.items[*i])
    }

    pub(crate) fn get_by_idx(&self, idx: &Idx) -> Option<&T> {
        self.idxs.get(idx).map(|i| &self.items[*i])
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
