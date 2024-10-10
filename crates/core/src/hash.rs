//! Hash types.

use std::{collections::HashMap, fmt::Display};

use rand::{distributions::Standard, prelude::Distribution};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::serialize::CanonicalSerialize;

pub(crate) const DEFAULT_SUPPORTED_HASH_ALGS: &[HashAlgId] =
    &[HashAlgId::SHA256, HashAlgId::BLAKE3, HashAlgId::KECCAK256];

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
        #[cfg(feature = "use_poseidon_halo2")]
        algs.insert(
            HashAlgId::POSEIDON_HALO2,
            Box::new(PoseidonHalo2::default()),
        );

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
    /// Poseidon hash algorithm (defined in the `poseidon-halo2` crate) with input padding.
    #[cfg(feature = "use_poseidon_halo2")]
    pub const POSEIDON_HALO2: Self = Self(4);

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedHash {
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// The hash value.
    pub value: Hash,
}

/// A hash value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Computes the hash of the provided blinded data.
    fn hash_blinded(&self, data: &Blinded<Vec<u8>>) -> Hash {
        self.hash_canonical(data)
    }
}

pub(crate) trait HashAlgorithmExt: HashAlgorithm {
    fn hash_canonical<T: CanonicalSerialize>(&self, data: &T) -> Hash {
        self.hash(&data.serialize())
    }

    fn hash_separated<T: DomainSeparator + CanonicalSerialize>(&self, data: &T) -> Hash {
        self.hash_prefixed(data.domain(), &data.serialize())
    }
}

impl<T: HashAlgorithm + ?Sized> HashAlgorithmExt for T {}

/// A hash blinder.
#[derive(Clone, Serialize, Deserialize)]
pub struct Blinder([u8; 16]);

impl Blinder {
    /// Returns a reference to the inner value.
    pub fn as_inner(&self) -> &[u8; 16] {
        &self.0
    }
}

opaque_debug::implement!(Blinder);

impl Distribution<Blinder> for Standard {
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
    pub(crate) fn new(data: T) -> Self {
        Self {
            data,
            blinder: rand::random(),
        }
    }

    pub(crate) fn new_with_blinder(data: T, blinder: Blinder) -> Self {
        Self { data, blinder }
    }

    pub(crate) fn data(&self) -> &T {
        &self.data
    }

    pub(crate) fn into_parts(self) -> (T, Blinder) {
        (self.data, self.blinder)
    }
}

/// A type with a domain separator which is used during hashing to mitigate type
/// confusion attacks.
pub(crate) trait DomainSeparator {
    /// Returns the domain separator for the type.
    fn domain(&self) -> &[u8];
}

macro_rules! impl_domain_separator {
    ($type:ty) => {
        impl $crate::hash::DomainSeparator for $type {
            fn domain(&self) -> &[u8] {
                use std::sync::LazyLock;

                // Computes a 16 byte hash of the types name to use as a domain separator.
                static DOMAIN: LazyLock<[u8; 16]> = LazyLock::new(|| {
                    let domain: [u8; 32] = blake3::hash(stringify!($type).as_bytes()).into();
                    domain[..16].try_into().unwrap()
                });

                &*DOMAIN
            }
        }
    };
}

pub(crate) use impl_domain_separator;

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
            super::Hash::new(hasher.finalize().as_slice())
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut hasher = ::sha2::Sha256::default();
            hasher.update(prefix);
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_slice())
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

#[cfg(feature = "use_poseidon_halo2")]
mod poseidon_halo2 {
    use super::Blinded;
    use poseidon_halo2::{hash as poseidon_hash, F};

    /// Poseidon hash algorithm with preimage padding.
    #[derive(Default, Clone)]
    pub struct PoseidonHalo2 {}

    /// How many least significant bytes of a field element are used to pack the preimage into.
    const BYTES_PER_FIELD_ELEMENT: usize = 31;

    /// Maximum allowed bytesize of the hash preimage.
    ///
    /// If more data than the allowed maximum needs to be hashed, then the data should be split up
    /// into chunks and each chunk should be hashed separately.
    pub const POSEIDON_MAX_INPUT_SIZE: usize = 434;

    impl super::HashAlgorithm for PoseidonHalo2 {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::POSEIDON_HALO2
        }

        fn hash(&self, _data: &[u8]) -> super::Hash {
            unimplemented!()
        }

        fn hash_prefixed(&self, _prefix: &[u8], _data: &[u8]) -> super::Hash {
            unimplemented!()
        }

        fn hash_blinded(&self, data: &Blinded<Vec<u8>>) -> super::Hash {
            let (data, blinder) = data.clone().into_parts();

            let mut field_elements = to_field_elements(&data);

            // Zero-pad to a total of 14 field elements.
            while field_elements.len() < 14 {
                field_elements.push(F::zero());
            }
            // The last field element is the salt.
            field_elements.push(to_field_elements(blinder.as_inner())[0]);

            poseidon_hash(&field_elements).into()
        }
    }

    fn to_field_elements(data: &[u8]) -> Vec<F> {
        data.chunks(BYTES_PER_FIELD_ELEMENT)
            .map(|bytes| {
                let mut bytes = bytes.to_vec();
                // Reverse to little-endian.
                bytes.reverse();
                let mut new_bytes = [0u8; 32];
                new_bytes[0..bytes.len()].copy_from_slice(&bytes);
                // Any random 31 bytes should be a valid BN256 field element.
                F::from_bytes(&new_bytes).expect("Input should always be canonical")
            })
            .collect::<Vec<_>>()
    }

    #[allow(clippy::from_over_into)]
    impl Into<super::Hash> for F {
        fn into(self) -> super::Hash {
            let mut bytes = self.to_bytes();
            // Reverse to big endian.
            bytes.reverse();
            super::Hash::new(&bytes)
        }
    }
}

#[cfg(feature = "use_poseidon_halo2")]
pub use poseidon_halo2::{PoseidonHalo2, POSEIDON_MAX_INPUT_SIZE};
