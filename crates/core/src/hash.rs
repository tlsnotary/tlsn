//! Hash types.

use std::{collections::HashMap, fmt::Display};

use rand::{distr::StandardUniform, prelude::Distribution};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum length of a hash value.
const MAX_LEN: usize = 64;

/// An error for [`HashProvider`].
#[derive(Debug, thiserror::Error)]
#[error("unknown hash algorithm id: {}", self.0)]
pub struct HashProviderError(HashAlgId);

/// Hash provider.
pub struct HashProvider {
    algs: HashMap<HashAlgId, Box<dyn HashAlgorithm + Send + Sync>>,
}

impl Default for HashProvider {
    fn default() -> Self {
        let mut algs: HashMap<_, Box<dyn HashAlgorithm + Send + Sync>> = HashMap::new();

        algs.insert(HashAlgId::SHA256, Box::new(Sha256::default()));
        algs.insert(HashAlgId::BLAKE3, Box::new(Blake3::default()));
        algs.insert(HashAlgId::KECCAK256, Box::new(Keccak256::default()));

        Self { algs }
    }
}

impl HashProvider {
    /// Sets a hash algorithm.
    ///
    /// This can be used to add or override implementations of hash algorithms.
    pub fn set_algorithm(
        &mut self,
        id: HashAlgId,
        algorithm: Box<dyn HashAlgorithm + Send + Sync>,
    ) {
        self.algs.insert(id, algorithm);
    }

    /// Returns the hash algorithm with the given identifier, or an error if the
    /// hash algorithm does not exist.
    pub fn get(
        &self,
        id: &HashAlgId,
    ) -> Result<&(dyn HashAlgorithm + Send + Sync), HashProviderError> {
        self.algs
            .get(id)
            .map(|alg| &**alg)
            .ok_or(HashProviderError(*id))
    }
}

/// A hash algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashAlgId(u8);

impl HashAlgId {
    /// SHA-256 hash algorithm.
    pub const SHA256: Self = Self(1);
    /// BLAKE3 hash algorithm.
    pub const BLAKE3: Self = Self(2);
    /// Keccak-256 hash algorithm.
    pub const KECCAK256: Self = Self(3);

    /// Creates a new hash algorithm identifier.
    ///
    /// # Panics
    ///
    /// Panics if the identifier is in the reserved range 0-127.
    ///
    /// # Arguments
    ///
    /// * id - Unique identifier for the hash algorithm.
    pub const fn new(id: u8) -> Self {
        assert!(id >= 128, "hash algorithm id range 0-127 is reserved");

        Self(id)
    }

    /// Returns the id as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        self.0
    }
}

impl Display for HashAlgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

/// A typed hash value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypedHash {
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// The hash value.
    pub value: Hash,
}

/// A hash value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash {
    // To avoid heap allocation, we use a fixed-size array.
    // 64 bytes should be sufficient for most hash algorithms.
    value: [u8; MAX_LEN],
    len: usize,
}

impl Default for Hash {
    fn default() -> Self {
        Self {
            value: [0u8; MAX_LEN],
            len: 0,
        }
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(&self.value[..self.len])
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use core::marker::PhantomData;
        use serde::de::{Error, SeqAccess, Visitor};

        struct HashVisitor<'de>(PhantomData<&'de ()>);

        impl<'de> Visitor<'de> for HashVisitor<'de> {
            type Value = Hash;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an array at most 64 bytes long")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut value = [0; MAX_LEN];
                let mut len = 0;

                while let Some(byte) = seq.next_element()? {
                    if len >= MAX_LEN {
                        return Err(A::Error::invalid_length(len, &self));
                    }

                    value[len] = byte;
                    len += 1;
                }

                Ok(Hash { value, len })
            }
        }

        deserializer.deserialize_seq(HashVisitor(PhantomData))
    }
}

impl Hash {
    /// Creates a new hash value.
    ///
    /// # Panics
    ///
    /// Panics if the length of the value is greater than 64 bytes.
    fn new(value: &[u8]) -> Self {
        assert!(
            value.len() <= MAX_LEN,
            "hash value must be at most 64 bytes"
        );

        let mut bytes = [0; MAX_LEN];
        bytes[..value.len()].copy_from_slice(value);

        Self {
            value: bytes,
            len: value.len(),
        }
    }

    /// Returns a byte slice of the hash value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value[..self.len]
    }
}

impl rs_merkle::Hash for Hash {
    const SIZE: usize = MAX_LEN;
}

impl TryFrom<Vec<u8>> for Hash {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > MAX_LEN {
            return Err("hash value must be at most 64 bytes");
        }

        let mut bytes = [0; MAX_LEN];
        bytes[..value.len()].copy_from_slice(&value);

        Ok(Self {
            value: bytes,
            len: value.len(),
        })
    }
}

impl From<Hash> for Vec<u8> {
    fn from(value: Hash) -> Self {
        value.value[..value.len].to_vec()
    }
}

/// A hashing algorithm.
pub trait HashAlgorithm {
    /// Returns the hash algorithm identifier.
    fn id(&self) -> HashAlgId;

    /// Computes the hash of the provided data.
    fn hash(&self, data: &[u8]) -> Hash;

    /// Computes the hash of the provided data with a prefix.
    fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> Hash;
}

/// A hash blinder.
#[derive(Clone, Serialize, Deserialize)]
pub struct Blinder([u8; 16]);

opaque_debug::implement!(Blinder);

impl Blinder {
    /// Returns the blinder as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Distribution<Blinder> for StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Blinder {
        let mut blinder = [0; 16];
        rng.fill(&mut blinder);
        Blinder(blinder)
    }
}

/// A blinded pre-image of a hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blinded<T> {
    data: T,
    blinder: Blinder,
}

impl<T> Blinded<T> {
    /// Creates a new blinded pre-image.
    pub fn new(data: T) -> Self {
        Self {
            data,
            blinder: rand::random(),
        }
    }

    /// Returns the data.
    pub fn data(&self) -> &T {
        &self.data
    }
}

mod sha2 {
    use ::sha2::Digest;

    /// SHA-256 hash algorithm.
    #[derive(Default, Clone)]
    pub struct Sha256 {}

    impl super::HashAlgorithm for Sha256 {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::SHA256
        }

        fn hash(&self, data: &[u8]) -> super::Hash {
            let mut hasher = ::sha2::Sha256::default();
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_ref())
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut hasher = ::sha2::Sha256::default();
            hasher.update(prefix);
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_ref())
        }
    }
}

pub use sha2::Sha256;

mod blake3 {

    /// BLAKE3 hash algorithm.
    #[derive(Default, Clone)]
    pub struct Blake3 {}

    impl super::HashAlgorithm for Blake3 {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::BLAKE3
        }

        fn hash(&self, data: &[u8]) -> super::Hash {
            super::Hash::new(::blake3::hash(data).as_bytes())
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut hasher = ::blake3::Hasher::new();
            hasher.update(prefix);
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_bytes())
        }
    }
}

pub use blake3::Blake3;

mod keccak {
    use tiny_keccak::Hasher;

    /// Keccak-256 hash algorithm.
    #[derive(Default, Clone)]
    pub struct Keccak256 {}

    impl super::HashAlgorithm for Keccak256 {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::KECCAK256
        }

        fn hash(&self, data: &[u8]) -> super::Hash {
            let mut hasher = tiny_keccak::Keccak::v256();
            hasher.update(data);
            let mut output = vec![0; 32];
            hasher.finalize(&mut output);
            super::Hash::new(&output)
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut hasher = tiny_keccak::Keccak::v256();
            hasher.update(prefix);
            hasher.update(data);
            let mut output = vec![0; 32];
            hasher.finalize(&mut output);
            super::Hash::new(&output)
        }
    }
}

pub use keccak::Keccak256;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::sha256(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak256(Keccak256::default())]
    fn test_hash_deterministic<H: HashAlgorithm>(#[case] hasher: H) {
        let data = b"hello world";
        let h1 = hasher.hash(data);
        let h2 = hasher.hash(data);
        assert_eq!(h1, h2);
        assert!(!h1.as_bytes().is_empty());
    }

    #[rstest]
    #[case::sha256(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak256(Keccak256::default())]
    fn test_hash_different_inputs<H: HashAlgorithm>(#[case] hasher: H) {
        let h1 = hasher.hash(b"hello");
        let h2 = hasher.hash(b"world");
        assert_ne!(h1, h2);
    }

    #[rstest]
    #[case::sha256(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak256(Keccak256::default())]
    fn test_hash_prefixed_differs<H: HashAlgorithm>(#[case] hasher: H) {
        let data = b"hello world";
        let h1 = hasher.hash(data);
        let h2 = hasher.hash_prefixed(b"prefix", data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sha256_known_vector() {
        let hasher = Sha256::default();
        let hash = hasher.hash(b"");
        // SHA-256 of empty string
        assert_eq!(
            hex::encode(hash.as_bytes()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_serialization_roundtrip() {
        let hasher = Sha256::default();
        let hash = hasher.hash(b"test data");

        let bytes = bincode::serialize(&hash).unwrap();
        let deserialized: Hash = bincode::deserialize(&bytes).unwrap();

        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_hash_try_from_vec() {
        let data = vec![1u8; 32];
        let hash = Hash::try_from(data.clone()).unwrap();
        assert_eq!(hash.as_bytes(), &data[..]);
    }

    #[test]
    fn test_hash_try_from_vec_too_long() {
        let data = vec![1u8; 65];
        assert!(Hash::try_from(data).is_err());
    }

    #[test]
    fn test_hash_into_vec() {
        let hasher = Sha256::default();
        let hash = hasher.hash(b"test");
        let bytes: Vec<u8> = hash.into();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_hash_provider_default() {
        let provider = HashProvider::default();
        assert!(provider.get(&HashAlgId::SHA256).is_ok());
        assert!(provider.get(&HashAlgId::BLAKE3).is_ok());
        assert!(provider.get(&HashAlgId::KECCAK256).is_ok());
    }

    #[test]
    fn test_hash_provider_unknown_id() {
        let provider = HashProvider::default();
        let custom_id = HashAlgId::new(200);
        assert!(provider.get(&custom_id).is_err());
    }

    #[test]
    fn test_hash_alg_id_as_u8() {
        assert_eq!(HashAlgId::SHA256.as_u8(), 1);
        assert_eq!(HashAlgId::BLAKE3.as_u8(), 2);
        assert_eq!(HashAlgId::KECCAK256.as_u8(), 3);
    }

    #[test]
    fn test_hash_alg_id_custom() {
        let id = HashAlgId::new(128);
        assert_eq!(id.as_u8(), 128);
    }

    #[test]
    #[should_panic]
    fn test_hash_alg_id_reserved() {
        let _ = HashAlgId::new(127);
    }

    #[test]
    fn test_blinder() {
        let blinder: Blinder = rand::random();
        assert_eq!(blinder.as_bytes().len(), 16);
    }

    #[test]
    fn test_blinded() {
        let blinded = Blinded::new(42u32);
        assert_eq!(*blinded.data(), 42);
    }

    #[test]
    fn test_typed_hash() {
        let hasher = Sha256::default();
        let hash = hasher.hash(b"test");
        let typed = TypedHash {
            alg: HashAlgId::SHA256,
            value: hash,
        };
        assert_eq!(typed.alg, HashAlgId::SHA256);
        assert_eq!(typed.value, hash);
    }
}
