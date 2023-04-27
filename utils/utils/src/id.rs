use std::sync::Arc;

/// A nested ID.
///
/// # Example
///
/// ```
/// # use utils::id::NestedId;
/// let id = NestedId::new("foo");
/// let id = id.append("bar");
/// assert_eq!(id.to_string(), "foo/bar");
/// let mut id = id.append_counter();
/// assert_eq!(id.to_string(), "foo/bar/0");
/// let new_id = id.increment();
/// assert_eq!(new_id.to_string(), "foo/bar/1");
/// assert!(new_id > id);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NestedId {
    String {
        id: String,
        root: Option<Arc<NestedId>>,
    },
    Counter {
        value: usize,
        root: Option<Arc<NestedId>>,
    },
}

impl NestedId {
    /// Create a new nested ID.
    pub fn new(id: &str) -> Self {
        NestedId::String {
            id: id.to_string(),
            root: None,
        }
    }

    /// Returns the root of this ID.
    pub fn root(&self) -> Option<&NestedId> {
        match self {
            NestedId::String { root, .. } => root,
            NestedId::Counter { root, .. } => root,
        }
        .as_ref()
        .map(|id| &**id)
    }

    /// Returns whether this ID is a counter ID.
    pub fn is_counter(&self) -> bool {
        match self {
            NestedId::String { .. } => false,
            NestedId::Counter { .. } => true,
        }
    }

    /// Returns whether this ID is a string ID.
    pub fn is_string(&self) -> bool {
        !self.is_counter()
    }

    /// Creates a new ID with `self` as the root.
    pub fn append_string(&self, id: &str) -> NestedId {
        Self::String {
            id: id.to_string(),
            root: Some(Arc::new(self.clone())),
        }
    }

    /// Creates a new counter ID with `self` as the root.
    pub fn append_counter(&self) -> NestedId {
        Self::Counter {
            value: 0,
            root: Some(Arc::new(self.clone())),
        }
    }

    /// Returns a new ID with the counter incremented.
    ///
    /// # Panics
    ///
    /// Panics if this ID is not a counter ID.
    pub fn increment(&self) -> Self {
        let mut id = self.clone();
        id.increment_in_place();
        id
    }

    /// Increments the counter of this ID, returning the previous value.
    ///
    /// # Panics
    ///
    /// Panics if this ID is not a counter ID.
    pub fn increment_in_place(&mut self) -> Self {
        let prev = self.clone();

        match self {
            NestedId::String { .. } => panic!("cannot increment a string ID"),
            NestedId::Counter { value, .. } => *value += 1,
        }

        prev
    }
}

impl ToString for NestedId {
    fn to_string(&self) -> String {
        match self {
            NestedId::String { id, root } => match root {
                Some(root) => format!("{}/{}", root.to_string(), id),
                None => id.to_string(),
            },
            NestedId::Counter { value, root } => match root {
                Some(root) => format!("{}/{}", root.to_string(), value),
                None => value.to_string(),
            },
        }
    }
}

impl PartialOrd for NestedId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_string().cmp(&other.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nested_id() {
        let id = NestedId::new("foo");
        assert_eq!(id.to_string(), "foo");
        assert_eq!(id.root(), None);

        let id = id.append_string("bar");
        assert_eq!(id.to_string(), "foo/bar");
        assert_eq!(id.root().unwrap().to_string(), "foo");
        assert!(id.is_string());

        let id = id.append_string("baz");
        assert_eq!(id.to_string(), "foo/bar/baz");
        assert_eq!(id.root().unwrap().to_string(), "foo/bar");
        assert!(id.is_string());

        let mut id = id.append_counter();
        assert_eq!(id.to_string(), "foo/bar/baz/0");
        assert_eq!(id.root().unwrap().to_string(), "foo/bar/baz");
        assert!(id.is_counter());

        id.increment_in_place();
        assert_eq!(id.to_string(), "foo/bar/baz/1");
        assert_eq!(id.root().unwrap().to_string(), "foo/bar/baz");
        assert!(id.is_counter());

        let new_id = id.increment();
        assert_eq!(new_id.to_string(), "foo/bar/baz/2");
        assert_eq!(new_id.root().unwrap().to_string(), "foo/bar/baz");
        assert!(new_id.is_counter());
        assert!(new_id > id);

        let root = id.root().unwrap().root().unwrap().root().unwrap();
        assert_eq!(root.to_string(), "foo");
    }
}
