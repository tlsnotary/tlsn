use serde::{Deserialize, Serialize};

/// A supported hashing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[repr(u8)]
pub enum HashAlgorithm {
    /// The SHA-256 hashing algorithm.
    #[cfg(feature = "sha2")]
    Sha256 = 0x00,
    /// The BLAKE3 hashing algorithm.
    #[cfg(feature = "blake3")]
    Blake3 = 0x01,
    /// The Keccak-256 f1600 hashing algorithm.
    #[cfg(feature = "keccak")]
    Keccak256 = 0x02,
}

impl HashAlgorithm {
    /// Returns the hash length in bytes.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            #[cfg(feature = "sha2")]
            Self::Sha256 => 32,
            #[cfg(feature = "blake3")]
            Self::Blake3 => 32,
            #[cfg(feature = "keccak")]
            Self::Keccak256 => 32,
        }
    }

    /// Hashes the provided message using the algorithm.
    pub fn hash(&self, msg: &[u8]) -> Hash {
        match self {
            #[cfg(feature = "sha2")]
            Self::Sha256 => Hash::Sha256(Sha256::hash(msg)),
            #[cfg(feature = "blake3")]
            Self::Blake3 => Hash::Blake3(Blake3::hash(msg)),
            #[cfg(feature = "keccak")]
            Self::Keccak256 => Hash::Keccak256(Keccak256::hash(msg)),
        }
    }
}

/// A hash value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "alg")]
pub enum Hash {
    /// A SHA-256 hash.
    #[cfg(feature = "sha2")]
    Sha256([u8; 32]),
    /// A BLAKE3 hash.
    #[cfg(feature = "blake3")]
    Blake3([u8; 32]),
    /// A Keccak-256 f1600 hash.
    #[cfg(feature = "keccak")]
    Keccak256([u8; 32]),
}

impl Hash {
    /// Returns the algorithm of the hash.
    pub fn algorithm(&self) -> HashAlgorithm {
        match self {
            #[cfg(feature = "sha2")]
            Self::Sha256(_) => HashAlgorithm::Sha256,
            #[cfg(feature = "blake3")]
            Self::Blake3(_) => HashAlgorithm::Blake3,
            #[cfg(feature = "keccak")]
            Self::Keccak256(_) => HashAlgorithm::Keccak256,
        }
    }
}

impl CanonicalSerialize for Hash {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.algorithm().len());
        bytes.push(self.algorithm() as u8);
        match self {
            #[cfg(feature = "sha2")]
            Self::Sha256(hash) => bytes.extend_from_slice(hash),
            #[cfg(feature = "blake3")]
            Self::Blake3(hash) => bytes.extend_from_slice(hash),
            #[cfg(feature = "keccak")]
            Self::Keccak256(hash) => bytes.extend_from_slice(hash),
        }
        bytes
    }
}

/// A hash of a subsequence of plaintext in the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextHash {
    /// The subsequence of plaintext.
    pub seq: SubsequenceIdx,
    /// The hash of the data.
    pub hash: Hash,
}

/// An opening of a hash of plaintext in the transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaintextHashOpening {
    data: Vec<u8>,
    nonce: [u8; 16],
    commitment: FieldId,
}

impl PlaintextHashOpening {
    /// Returns the field id of the commitment this opening corresponds to.
    pub fn commitment_id(&self) -> &FieldId {
        &self.commitment
    }

    /// Verifies the opening of the hash, returning the subsequence of plaintext.
    ///
    /// # Arguments
    ///
    /// * `commitment` - The commitment attested to by a Notary.
    pub fn verify(&self, commitment: &PlaintextHash) -> Result<Subsequence, ()> {
        let mut opening = self.data.clone();
        opening.extend_from_slice(&self.nonce);

        let expected_hash = commitment.hash.algorithm().hash(&opening);

        if expected_hash == commitment.hash {
            Ok(Subsequence {
                idx: commitment.seq.clone(),
                data: self.data.clone(),
            })
        } else {
            Err(())
        }
    }
}

/// A hashing algorithm supported by TLSNotary.
pub(crate) trait Hasher:
    rs_merkle::Hasher<Hash = Self::Output> + crate::sealed::Sealed
{
    /// The output of the hasher.
    type Output: Copy
        + PartialEq
        + Eq
        + std::hash::Hash
        + AsRef<[u8]>
        + for<'a> TryFrom<&'a [u8]>
        + Serialize
        + for<'de> Deserialize<'de>;
    /// The length of the hash in bytes.
    const BYTE_LEN: usize;

    /// Creates a new hash which can be updated incrementally.
    fn new() -> Self;

    /// Returns the algorithm of the hash.
    fn algorithm() -> HashAlgorithm;

    /// Updates the hash with the given data.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash.
    fn finalize(self) -> Self::Output;

    /// Computes the hash of the given data.
    fn hash(data: &[u8]) -> Self::Output
    where
        Self: Sized,
    {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

#[cfg(feature = "sha2")]
mod sha2 {
    use ::sha2::Digest;

    /// The SHA-256 hashing algorithm.
    #[derive(Clone)]
    pub struct Sha256(::sha2::Sha256);

    opaque_debug::implement!(Sha256);

    impl crate::sealed::Sealed for Sha256 {}

    impl super::Hasher for Sha256 {
        type Output = [u8; 32];
        const BYTE_LEN: usize = 32;

        fn new() -> Self {
            Sha256(::sha2::Sha256::new())
        }

        fn algorithm() -> super::HashAlgorithm {
            super::HashAlgorithm::Sha256
        }

        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }

        fn finalize(self) -> Self::Output {
            self.0.finalize().into()
        }
    }

    impl rs_merkle::Hasher for Sha256 {
        type Hash = [u8; 32];

        fn hash(data: &[u8]) -> Self::Hash {
            <Self as super::Hasher>::hash(data)
        }
    }
}

#[cfg(feature = "sha2")]
pub use sha2::Sha256;

#[cfg(feature = "blake3")]
mod blake3 {
    /// The BLAKE3 hashing algorithm.
    #[derive(Clone)]
    pub struct Blake3(::blake3::Hasher);

    opaque_debug::implement!(Blake3);

    impl crate::sealed::Sealed for Blake3 {}

    impl super::Hasher for Blake3 {
        type Output = [u8; 32];
        const BYTE_LEN: usize = 32;

        fn new() -> Self {
            Blake3(::blake3::Hasher::new())
        }

        fn algorithm() -> super::HashAlgorithm {
            super::HashAlgorithm::Blake3
        }

        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }

        fn finalize(self) -> Self::Output {
            self.0.finalize().into()
        }
    }

    impl rs_merkle::Hasher for Blake3 {
        type Hash = [u8; 32];

        fn hash(data: &[u8]) -> Self::Hash {
            <Self as super::Hasher>::hash(data)
        }
    }
}

#[cfg(feature = "blake3")]
pub use blake3::Blake3;

#[cfg(feature = "keccak")]
mod keccak {
    use tiny_keccak::Hasher;

    /// The Keccak-256 hashing algorithm.
    #[derive(Clone)]
    pub struct Keccak256(tiny_keccak::Keccak);

    opaque_debug::implement!(Keccak256);

    impl crate::sealed::Sealed for Keccak256 {}

    impl super::Hasher for Keccak256 {
        type Output = [u8; 32];
        const BYTE_LEN: usize = 32;

        fn new() -> Self {
            Keccak256(tiny_keccak::Keccak::v256())
        }

        fn algorithm() -> super::HashAlgorithm {
            super::HashAlgorithm::Keccak256
        }

        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }

        fn finalize(self) -> Self::Output {
            let mut output = [0; 32];
            self.0.finalize(&mut output);
            output
        }
    }

    impl rs_merkle::Hasher for Keccak256 {
        type Hash = [u8; 32];

        fn hash(data: &[u8]) -> Self::Hash {
            <Self as super::Hasher>::hash(data)
        }
    }
}

#[cfg(feature = "keccak")]
pub use keccak::Keccak256;

use crate::{
    attestation::FieldId,
    serialize::CanonicalSerialize,
    transcript::{Subsequence, SubsequenceIdx},
};
