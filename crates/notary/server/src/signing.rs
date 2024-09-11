use core::fmt;
use std::sync::{Arc, Mutex};

use k256::ecdsa::signature::SignerMut;
use pkcs8::{der::Encode, AssociatedOid, DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo};
use tlsn_core::signing::{Signature, SignatureAlgId, SignatureError, Signer, VerifyingKey};
use tracing::error;

/// A cryptographic key used for signing attestations.
#[derive(Clone)]
pub struct AttestationKey {
    alg_id: SignatureAlgId,
    key: Arc<Mutex<SigningKey>>,
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

        Ok(Self {
            alg_id,
            key: Arc::new(Mutex::new(key)),
        })
    }
}

impl Signer for AttestationKey {
    fn alg_id(&self) -> SignatureAlgId {
        self.alg_id
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
        let mut key = self.key.lock().unwrap();
        Ok(Signature {
            alg: self.alg_id,
            data: match &mut (*key) {
                SigningKey::Secp256k1(key) => {
                    SignerMut::<k256::ecdsa::Signature>::sign(key, msg).to_vec()
                }
                SigningKey::Secp256r1(key) => {
                    SignerMut::<p256::ecdsa::Signature>::sign(key, msg).to_vec()
                }
            },
        })
    }

    fn verifying_key(&self) -> VerifyingKey {
        todo!()
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
