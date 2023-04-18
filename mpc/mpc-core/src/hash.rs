//! Traits and types for hashing serde serializable types.
//!
//! All types are serialized using [Binary Canonical Serialization (BCS)](https://docs.rs/bcs/latest/bcs/)
//!
//! Default implementations use [Blake3](https://docs.rs/blake3/latest/blake3/) as the hash function

use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// A secure hash
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A trait for hashing serde serializable types
pub trait SecureHash
where
    Self: serde::Serialize,
{
    /// Creates a hash of self
    fn hash(&self) -> Hash {
        let bytes = bcs::to_bytes(self).expect("serialization should not fail");
        Hash(blake3::hash(&bytes).into())
    }
}

impl<T> SecureHash for T where T: serde::Serialize {}

/// A trait for hashing serde serializable types with a domain separator
pub trait DomainSeparatedHash
where
    Self: serde::Serialize,
{
    /// Creates a new hasher seeded with the domain separator
    fn hasher() -> Hasher;

    /// Creates a hash of self with a domain separator
    fn domain_separated_hash(&self) -> Hash {
        let bytes = bcs::to_bytes(self).expect("serialization should not fail");
        let mut hasher = Self::hasher();
        hasher.update(&bytes);
        Hash(hasher.finalize().into())
    }
}

/// A macro for implementing the `DomainSeparatedHash` trait
///
/// # Example
///
/// ```ignore
/// # use mpc_core::hash::DomainSeparatedHash;
/// # use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// pub struct Foo(u64);
///
/// // All instances of `Foo` will be hashed with the domain separator "FOO"
/// impl_domain_separated_hash!(Foo, "FOO");
/// ```
#[macro_export]
macro_rules! impl_domain_separated_hash {
    ($ty:ty, $domain:expr) => {
        impl DomainSeparatedHash for $ty {
            fn hasher() -> Hasher {
                static HASHER: once_cell::sync::Lazy<Hasher> = once_cell::sync::Lazy::new(|| {
                    let mut hasher = Hasher::new();
                    hasher.update($domain.as_bytes());
                    // Fixed length seed computed from the domain salt
                    let seed: [u8; 32] = hasher.finalize().into();

                    let mut hasher = Hasher::new();
                    hasher.update(&seed);
                    hasher
                });

                HASHER.clone()
            }
        }
    };
}
