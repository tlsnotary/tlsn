use tlsn_core::hash::{Hash, HashAlgId, HashAlgorithm};

use crate::serialize::{CanonicalSerialize, DomainSeparator};

pub(crate) const DEFAULT_SUPPORTED_HASH_ALGS: &[HashAlgId] =
    &[HashAlgId::SHA256, HashAlgId::BLAKE3, HashAlgId::KECCAK256];

pub(crate) trait HashAlgorithmExt: HashAlgorithm {
    #[allow(dead_code)]
    fn hash_canonical<T: CanonicalSerialize>(&self, data: &T) -> Hash {
        self.hash(&data.serialize())
    }

    fn hash_separated<T: DomainSeparator + CanonicalSerialize>(&self, data: &T) -> Hash {
        self.hash_prefixed(data.domain(), &data.serialize())
    }
}

impl<T: HashAlgorithm + ?Sized> HashAlgorithmExt for T {}
