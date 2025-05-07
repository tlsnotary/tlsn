use const_oid::db::rfc5912::ID_EC_PUBLIC_KEY as OID_EC_PUBLIC_KEY;
use core::fmt;
use pkcs8::{
    der::{self, pem::PemLabel, Encode},
    spki::{DynAssociatedAlgorithmIdentifier, SubjectPublicKeyInfoRef},
    AssociatedOid, DecodePrivateKey, LineEnding, PrivateKeyInfo,
};
use rand06_compat::Rand0_6CompatExt;
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
    pub fn random(alg_id: &str) -> Self {
        match alg_id.to_uppercase().as_str() {
            "SECP256K1" => Self {
                alg_id: SignatureAlgId::SECP256K1,
                key: SigningKey::Secp256k1(k256::ecdsa::SigningKey::random(
                    &mut rand::rng().compat(),
                )),
            },
            "SECP256R1" => Self {
                alg_id: SignatureAlgId::SECP256R1,
                key: SigningKey::Secp256r1(p256::ecdsa::SigningKey::random(
                    &mut rand::rng().compat(),
                )),
            },
            alg_id => unimplemented!("unsupported signature algorithm: {alg_id} — only secp256k1 and secp256r1 are supported now"),
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

    /// Returns the verifying key in compressed bytes.
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        match self.key {
            SigningKey::Secp256k1(ref key) => key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            SigningKey::Secp256r1(ref key) => key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        }
    }

    /// Returns the verifying key in compressed PEM format.
    pub fn verifying_key_pem(&self) -> Result<String, pkcs8::spki::Error> {
        let algorithm = match &self.key {
            SigningKey::Secp256k1(key) => key.verifying_key().algorithm_identifier()?,
            SigningKey::Secp256r1(key) => key.verifying_key().algorithm_identifier()?,
        };
        let verifying_key_bytes = self.verifying_key_bytes();
        let subject_public_key = der::asn1::BitStringRef::new(0, &verifying_key_bytes)?;

        let der: der::Document = pkcs8::SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        }
        .try_into()?;

        let pem = der.to_pem(SubjectPublicKeyInfoRef::PEM_LABEL, LineEnding::LF)?;

        Ok(pem)
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
