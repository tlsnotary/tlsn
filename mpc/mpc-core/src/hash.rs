//! Traits and types for hashing serde serializable types.
//!
//! All types are serialized using [Binary Canonical Serialization (BCS)](https://docs.rs/bcs/latest/bcs/)
//!
//! Default implementations use [Blake3](https://docs.rs/blake3/latest/blake3/) as the hash function

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::serialize::CanonicalSerialize;

/// A secure hash
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Returns the hash as a byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A trait for hashing serde serializable types
pub trait SecureHash
where
    Self: CanonicalSerialize,
{
    /// Creates a hash of self
    fn hash(&self) -> Hash {
        Hash(blake3::hash(&self.to_bytes()).into())
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
        let mut hasher = Self::hasher();
        hasher.update(&self.to_bytes());
        Hash(hasher.finalize().into())
    }
}

/// A macro for implementing the `DomainSeparatedHash` trait
///
/// # Example
///
/// ```
/// # use mpc_core::{hash::DomainSeparatedHash, impl_domain_separated_hash};
/// # use serde::Serialize;
///
/// #[derive(Serialize)]
/// pub struct Foo(u64);
///
/// // All instances of `Foo` will be hashed with the domain separator "FOO"
/// impl_domain_separated_hash!(Foo, "FOO");
///
/// fn main() {
///     let foo = Foo(42u64);
///     let hash = foo.domain_separated_hash();
///     
///     let mut seed_hasher = blake3::Hasher::new();
///     seed_hasher.update("FOO".as_bytes());
///     let seed = seed_hasher.finalize();
///
///     let mut hasher = blake3::Hasher::new();
///     hasher.update(seed.as_bytes().as_slice());
///     hasher.update(42u64.to_le_bytes().as_slice());
///     let expected_hash = hasher.finalize();
///
///     assert_eq!(hash.as_bytes(), expected_hash.as_bytes());
/// }
/// ```
#[macro_export]
macro_rules! impl_domain_separated_hash {
    ($ty:ty, $domain:expr) => {
        impl DomainSeparatedHash for $ty {
            fn hasher() -> blake3::Hasher {
                static HASHER: once_cell::sync::Lazy<blake3::Hasher> =
                    once_cell::sync::Lazy::new(|| {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update($domain.as_bytes());
                        // Fixed length seed computed from the domain salt
                        let seed = hasher.finalize();

                        let mut hasher = blake3::Hasher::new();
                        hasher.update(seed.as_bytes().as_slice());
                        hasher
                    });

                HASHER.clone()
            }
        }
    };
}
