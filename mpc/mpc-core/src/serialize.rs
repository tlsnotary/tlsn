//! Traits for canonical serialization of serde serializable types.

/// A trait for canonical serialization of serde serializable types.
///
/// This trait provides a default implementation which uses
/// [Binary Canonical Serialization (BCS)](https://docs.rs/bcs/latest/bcs/).
pub trait CanonicalSerialize: serde::Serialize {
    /// Serializes self into a byte vector
    fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("serialization should not fail")
    }
}

impl<T> CanonicalSerialize for T where T: serde::Serialize {}
