use const_oid::db::rfc5912::ID_EC_PUBLIC_KEY as OID_EC_PUBLIC_KEY;
use core::fmt;
use pkcs8::{
    der::{self, Encode},
    spki::DynAssociatedAlgorithmIdentifier,
    AssociatedOid, DecodePrivateKey, EncodePublicKey, LineEnding, PrivateKeyInfo,
};
use rand06_compat::Rand0_6CompatExt;
use tlsn_core::signing::{KeyAlgId, Secp256k1Signer, Secp256r1Signer, SignatureAlgId, Signer};
use tracing::error;

/// A cryptographic key used for signing attestations.
pub struct AttestationKey {
    alg_id: SignatureAlgId,
    key: SigningKey,
}

impl TryFrom<PrivateKeyInfo<'_>> for AttestationKey {
    type Error = pkcs8::Error;

    fn try_from(pkcs8: PrivateKeyInfo<'_>) -> Result<Self, Self::Error> {
        // For now we only support elliptic curve keys.
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
    /// Samples a new attestation key of the given signature algorithm.
    pub fn random(alg_id: SignatureAlgId) -> Self {
        match alg_id {
            SignatureAlgId::SECP256K1 => Self {
                alg_id,
                key: SigningKey::Secp256k1(k256::ecdsa::SigningKey::random(
                    &mut rand::rng().compat(),
                )),
            },
            SignatureAlgId::SECP256R1 => Self {
                alg_id,
                key: SigningKey::Secp256r1(p256::ecdsa::SigningKey::random(
                    &mut rand::rng().compat(),
                )),
            },
            _ => unimplemented!(),
        }
    }

    /// Generates the public key corresponding to this attestation key.  
    pub fn public_key(&self) -> PublicKey {
        match self.alg_id {
            SignatureAlgId::SECP256K1 => PublicKey::new(KeyAlgId::K256, self.key.verifying_key()),
            SignatureAlgId::SECP256R1 => PublicKey::new(KeyAlgId::P256, self.key.verifying_key()),
            _ => unimplemented!(),
        }
    }

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

impl SigningKey {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            SigningKey::Secp256k1(key) => VerifyingKey::K256(*key.verifying_key()),
            SigningKey::Secp256r1(key) => VerifyingKey::P256(*key.verifying_key()),
        }
    }
}

/// Corresponding public key of the attestation key.
pub struct PublicKey {
    #[allow(dead_code)]
    alg_id: KeyAlgId,
    key: VerifyingKey,
}

impl PublicKey {
    fn new(alg_id: KeyAlgId, key: VerifyingKey) -> Self {
        Self { alg_id, key }
    }

    /// Converts the public key into PEM encoding in compressed form.
    pub fn to_pem(&self) -> Result<String, pkcs8::Error> {
        Ok(self.key.to_public_key_pem(LineEnding::LF)?)
    }

    #[cfg(feature = "tee_quote")]
    /// Coverts the public key into bytes in compressed form.
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        self.key.to_compressed_bytes()
    }
}

enum VerifyingKey {
    K256(k256::ecdsa::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

impl VerifyingKey {
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let encoded_point = match self {
            VerifyingKey::K256(key) => key.to_encoded_point(true),
            VerifyingKey::P256(key) => key.to_encoded_point(true),
        };
        encoded_point.as_bytes().to_vec()
    }
}
// The default `EncodePublicKey` impl for both `k256::ecdsa::VerifyingKey` and
// `p256::ecdsa::VerifyingKey` are serializing the public key in uncompressed
// format. This overrides that to obtain the compressed format.
//
// Reference: https://github.com/RustCrypto/traits/blob/f44963a897af10d125efe3af89b20930ebe4a999/elliptic-curve/src/public_key.rs#L476-L493
impl EncodePublicKey for VerifyingKey {
    fn to_public_key_der(&self) -> Result<der::Document, pkcs8::spki::Error> {
        let algorithm = match self {
            VerifyingKey::K256(key) => key.algorithm_identifier()?,
            VerifyingKey::P256(key) => key.algorithm_identifier()?,
        };

        let public_key_bytes = self.to_compressed_bytes();
        let subject_public_key = der::asn1::BitStringRef::new(0, &public_key_bytes)?;

        pkcs8::SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        }
        .try_into()
    }
}
