use core::fmt;

use pkcs8::{der::Encode, AssociatedOid, DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo};
use tlsn_core::signing::{Secp256k1Signer, Secp256r1Signer, SignatureAlgId, Signer};
use tracing::error;

/// A cryptographic key used for signing attestations.
pub struct AttestationKey {
    alg_id: SignatureAlgId,
    key: SigningKey,
}

impl TryFrom<PrivateKeyInfo<'_>> for AttestationKey {
    type Error = pkcs8::Error;

    fn try_from(pkcs8: PrivateKeyInfo<'_>) -> Result<Self, Self::Error> {
        const OID_EC_PUBLIC_KEY: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

        // For now we only support elliptic curve keys
        if pkcs8.algorithm.oid != OID_EC_PUBLIC_KEY {
            error!("unsupported key algorithm OID: {:?}", pkcs8.algorithm.oid);

            return Err(pkcs8::Error::KeyMalformed);
        }

        let (alg_id, key) = match pkcs8.algorithm.parameters_oid()? {
            k256::Secp256k1::OID => {
                let key = k256::ecdsa::SigningKey::from_pkcs8_der(&pkcs8.to_der()?)
                    .map_err(|_| pkcs8::Error::KeyMalformed)?;
                (SignatureAlgId::SECP256K1, SigningKey::Secp256k1(key))
            }
            p256::NistP256::OID => {
                let key = p256::ecdsa::SigningKey::from_pkcs8_der(&pkcs8.to_der()?)
                    .map_err(|_| pkcs8::Error::KeyMalformed)?;
                (SignatureAlgId::SECP256R1, SigningKey::Secp256r1(key))
            }
            oid => {
                error!("unsupported curve OID: {:?}", oid);

                return Err(pkcs8::Error::KeyMalformed);
            }
        };

        Ok(Self { alg_id, key })
    }
}

impl AttestationKey {
    /// Creates a new signer using this key.
    pub fn into_signer(self) -> Box<dyn Signer + Send + Sync> {
        match self.key {
            SigningKey::Secp256k1(key) => {
                Box::new(Secp256k1Signer::new(&key.to_bytes()).expect("key should be valid"))
            }
            SigningKey::Secp256r1(key) => {
                Box::new(Secp256r1Signer::new(&key.to_bytes()).expect("key should be valid"))
            }
        }
    }
}

impl fmt::Debug for AttestationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationKey")
            .field("alg_id", &self.alg_id)
            .finish_non_exhaustive()
    }
}

enum SigningKey {
    Secp256k1(k256::ecdsa::SigningKey),
    Secp256r1(p256::ecdsa::SigningKey),
}
