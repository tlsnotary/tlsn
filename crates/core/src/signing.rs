//! Cryptographic signatures.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::hash::impl_domain_separator;

/// Key algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyAlgId(u8);

impl KeyAlgId {
    /// secp256k1 elliptic curve key algorithm.
    pub const K256: Self = Self(1);
    /// NIST P-256 elliptic curve key algorithm.
    pub const P256: Self = Self(2);

    /// Creates a new key algorithm identifier.
    ///
    /// # Panics
    ///
    /// Panics if the identifier is in the reserved range 0-127.
    ///
    /// # Arguments
    ///
    /// * id - Unique identifier for the key algorithm.
    pub const fn new(id: u8) -> Self {
        assert!(id >= 128, "key algorithm id range 0-127 is reserved");

        Self(id)
    }

    /// Returns the id as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        self.0
    }
}

impl std::fmt::Display for KeyAlgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            KeyAlgId::K256 => write!(f, "k256"),
            KeyAlgId::P256 => write!(f, "p256"),
            _ => write!(f, "custom({:02x})", self.0),
        }
    }
}

/// Signature algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignatureAlgId(u8);

impl SignatureAlgId {
    /// secp256k1 signature algorithm.
    pub const SECP256K1: Self = Self(1);
    /// secp256r1 signature algorithm.
    pub const SECP256R1: Self = Self(2);

    /// Creates a new signature algorithm identifier.
    ///
    /// # Panics
    ///
    /// Panics if the identifier is in the reserved range 0-127.
    ///
    /// # Arguments
    ///
    /// * id - Unique identifier for the signature algorithm.
    pub const fn new(id: u8) -> Self {
        assert!(id >= 128, "signature algorithm id range 0-127 is reserved");

        Self(id)
    }

    /// Returns the id as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        self.0
    }
}

impl std::fmt::Display for SignatureAlgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            SignatureAlgId::SECP256K1 => write!(f, "secp256k1"),
            SignatureAlgId::SECP256R1 => write!(f, "secp256r1"),
            _ => write!(f, "custom({:02x})", self.0),
        }
    }
}

/// Unknown signature algorithm error.
#[derive(Debug, thiserror::Error)]
#[error("unknown signature algorithm id: {0:?}")]
pub struct UnknownSignatureAlgId(SignatureAlgId);

/// Provider of signers.
#[derive(Default)]
pub struct SignerProvider {
    signers: HashMap<SignatureAlgId, Box<dyn Signer + Send + Sync>>,
}

impl SignerProvider {
    /// Returns the supported signature algorithms.
    pub fn supported_algs(&self) -> impl Iterator<Item = SignatureAlgId> + '_ {
        self.signers.keys().copied()
    }

    /// Configures a signer.
    pub fn set_signer(&mut self, signer: Box<dyn Signer + Send + Sync>) {
        self.signers.insert(signer.alg_id(), signer);
    }

    /// Configures a secp256k1 signer with the provided signing key.
    pub fn set_secp256k1(&mut self, key: &[u8]) -> Result<&mut Self, SignerError> {
        self.set_signer(Box::new(Secp256k1Signer::new(key)?));

        Ok(self)
    }

    /// Configures a secp256r1 signer with the provided signing key.
    pub fn set_secp256r1(&mut self, key: &[u8]) -> Result<&mut Self, SignerError> {
        self.set_signer(Box::new(Secp256r1Signer::new(key)?));

        Ok(self)
    }

    /// Returns a signer for the given algorithm.
    pub(crate) fn get(
        &self,
        alg: &SignatureAlgId,
    ) -> Result<&(dyn Signer + Send + Sync), UnknownSignatureAlgId> {
        self.signers
            .get(alg)
            .map(|s| &**s)
            .ok_or(UnknownSignatureAlgId(*alg))
    }
}

/// Error for [`Signer`].
#[derive(Debug, thiserror::Error)]
#[error("signer error: {0}")]
pub struct SignerError(String);

/// Cryptographic signer.
pub trait Signer {
    /// Returns the algorithm used by this signer.
    fn alg_id(&self) -> SignatureAlgId;

    /// Signs the message.
    fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError>;

    /// Returns the verifying key for this signer.
    fn verifying_key(&self) -> VerifyingKey;
}

/// Provider of signature verifiers.
pub struct SignatureVerifierProvider {
    verifiers: HashMap<SignatureAlgId, Box<dyn SignatureVerifier + Send + Sync>>,
}

impl Default for SignatureVerifierProvider {
    fn default() -> Self {
        let mut verifiers = HashMap::new();

        verifiers.insert(SignatureAlgId::SECP256K1, Box::new(Secp256k1Verifier) as _);
        verifiers.insert(SignatureAlgId::SECP256R1, Box::new(Secp256r1Verifier) as _);

        Self { verifiers }
    }
}

impl SignatureVerifierProvider {
    /// Configures a signature verifier.
    pub fn set_verifier(&mut self, verifier: Box<dyn SignatureVerifier + Send + Sync>) {
        self.verifiers.insert(verifier.alg_id(), verifier);
    }

    /// Returns the verifier for the given algorithm.
    pub(crate) fn get(
        &self,
        alg: &SignatureAlgId,
    ) -> Result<&(dyn SignatureVerifier + Send + Sync), UnknownSignatureAlgId> {
        self.verifiers
            .get(alg)
            .map(|s| &**s)
            .ok_or(UnknownSignatureAlgId(*alg))
    }
}

/// Signature verifier.
pub trait SignatureVerifier {
    /// Returns the algorithm used by this verifier.
    fn alg_id(&self) -> SignatureAlgId;

    /// Verifies the signature.
    fn verify(&self, key: &VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError>;
}

/// Verifying key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifyingKey {
    /// The key algorithm.
    pub alg: KeyAlgId,
    /// The key data.
    pub data: Vec<u8>,
}

impl_domain_separator!(VerifyingKey);

/// Error occurred while verifying a signature.
#[derive(Debug, thiserror::Error)]
#[error("signature verification failed: {0}")]
pub struct SignatureError(String);

/// A signature.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Signature {
    /// The algorithm used to sign the data.
    pub alg: SignatureAlgId,
    /// The signature data.
    pub data: Vec<u8>,
}

mod secp256k1 {
    use std::sync::{Arc, Mutex};

    use k256::ecdsa::{
        signature::{SignerMut, Verifier},
        Signature as Secp256K1Signature, SigningKey,
    };

    use super::*;

    /// secp256k1 signer.
    pub struct Secp256k1Signer(Arc<Mutex<SigningKey>>);

    impl Secp256k1Signer {
        /// Creates a new secp256k1 signer with the provided signing key.
        pub fn new(key: &[u8]) -> Result<Self, SignerError> {
            SigningKey::from_slice(key)
                .map(|key| Self(Arc::new(Mutex::new(key))))
                .map_err(|_| SignerError("invalid key".to_string()))
        }
    }

    impl Signer for Secp256k1Signer {
        fn alg_id(&self) -> SignatureAlgId {
            SignatureAlgId::SECP256K1
        }

        fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
            let sig: Secp256K1Signature = self.0.lock().unwrap().sign(msg);

            Ok(Signature {
                alg: SignatureAlgId::SECP256K1,
                data: sig.to_vec(),
            })
        }

        fn verifying_key(&self) -> VerifyingKey {
            let key = self.0.lock().unwrap().verifying_key().to_sec1_bytes();

            VerifyingKey {
                alg: KeyAlgId::K256,
                data: key.to_vec(),
            }
        }
    }

    /// secp256k1 verifier.
    pub struct Secp256k1Verifier;

    impl SignatureVerifier for Secp256k1Verifier {
        fn alg_id(&self) -> SignatureAlgId {
            SignatureAlgId::SECP256K1
        }

        fn verify(&self, key: &VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
            if key.alg != KeyAlgId::K256 {
                return Err(SignatureError("key algorithm is not k256".to_string()));
            }

            let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&key.data)
                .map_err(|_| SignatureError("invalid k256 key".to_string()))?;

            let sig = Secp256K1Signature::from_slice(sig)
                .map_err(|_| SignatureError("invalid secp256k1 signature".to_string()))?;

            key.verify(msg, &sig).map_err(|_| {
                SignatureError("secp256k1 signature verification failed".to_string())
            })?;

            Ok(())
        }
    }
}

pub use secp256k1::{Secp256k1Signer, Secp256k1Verifier};

mod secp256r1 {
    use std::sync::{Arc, Mutex};

    use p256::ecdsa::{
        signature::{SignerMut, Verifier},
        Signature as Secp256R1Signature, SigningKey,
    };

    use super::*;

    /// secp256r1 signer.
    pub struct Secp256r1Signer(Arc<Mutex<SigningKey>>);

    impl Secp256r1Signer {
        /// Creates a new secp256r1 signer with the provided signing key.
        pub fn new(key: &[u8]) -> Result<Self, SignerError> {
            SigningKey::from_slice(key)
                .map(|key| Self(Arc::new(Mutex::new(key))))
                .map_err(|_| SignerError("invalid key".to_string()))
        }
    }

    impl Signer for Secp256r1Signer {
        fn alg_id(&self) -> SignatureAlgId {
            SignatureAlgId::SECP256R1
        }

        fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
            let sig: Secp256R1Signature = self.0.lock().unwrap().sign(msg);

            Ok(Signature {
                alg: SignatureAlgId::SECP256R1,
                data: sig.to_vec(),
            })
        }

        fn verifying_key(&self) -> VerifyingKey {
            let key = self.0.lock().unwrap().verifying_key().to_sec1_bytes();

            VerifyingKey {
                alg: KeyAlgId::P256,
                data: key.to_vec(),
            }
        }
    }

    /// secp256r1 verifier.
    pub struct Secp256r1Verifier;

    impl SignatureVerifier for Secp256r1Verifier {
        fn alg_id(&self) -> SignatureAlgId {
            SignatureAlgId::SECP256R1
        }

        fn verify(&self, key: &VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
            if key.alg != KeyAlgId::P256 {
                return Err(SignatureError("key algorithm is not p256".to_string()));
            }

            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.data)
                .map_err(|_| SignatureError("invalid p256 key".to_string()))?;

            let sig = Secp256R1Signature::from_slice(sig)
                .map_err(|_| SignatureError("invalid secp256r1 signature".to_string()))?;

            key.verify(msg, &sig).map_err(|_| {
                SignatureError("secp256r1 signature verification failed".to_string())
            })?;

            Ok(())
        }
    }
}

pub use secp256r1::{Secp256r1Signer, Secp256r1Verifier};

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;
    use rstest::{fixture, rstest};

    #[fixture]
    #[once]
    fn secp256k1_signer() -> Secp256k1Signer {
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        Secp256k1Signer::new(&signing_key.to_bytes()).unwrap()
    }

    #[fixture]
    #[once]
    fn secp256r1_signer() -> Secp256r1Signer {
        let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        Secp256r1Signer::new(&signing_key.to_bytes()).unwrap()
    }

    #[rstest]
    fn test_secp256k1_success(secp256k1_signer: &Secp256k1Signer) {
        assert_eq!(secp256k1_signer.alg_id(), SignatureAlgId::SECP256K1);

        let msg = "test payload";
        let signature = secp256k1_signer.sign(msg.as_bytes()).unwrap();
        let verifying_key = secp256k1_signer.verifying_key();

        let verifier = Secp256k1Verifier {};
        assert_eq!(verifier.alg_id(), SignatureAlgId::SECP256K1);
        let result = verifier.verify(&verifying_key, msg.as_bytes(), &signature.data);
        assert!(result.is_ok());
    }

    #[rstest]
    fn test_secp256r1_success(secp256r1_signer: &Secp256r1Signer) {
        assert_eq!(secp256r1_signer.alg_id(), SignatureAlgId::SECP256R1);

        let msg = "test payload";
        let signature = secp256r1_signer.sign(msg.as_bytes()).unwrap();
        let verifying_key = secp256r1_signer.verifying_key();

        let verifier = Secp256r1Verifier {};
        assert_eq!(verifier.alg_id(), SignatureAlgId::SECP256R1);
        let result = verifier.verify(&verifying_key, msg.as_bytes(), &signature.data);
        assert!(result.is_ok());
    }

    #[rstest]
    #[case::wrong_signer(&secp256r1_signer(), false, false)]
    #[case::corrupted_signature(&secp256k1_signer(), true, false)]
    #[case::wrong_signature(&secp256k1_signer(), false, true)]
    fn test_failure(
        #[case] signer: &dyn Signer,
        #[case] corrupted_signature: bool,
        #[case] wrong_signature: bool,
    ) {
        let msg = "test payload";
        let mut signature = signer.sign(msg.as_bytes()).unwrap();
        let verifying_key = signer.verifying_key();

        if corrupted_signature {
            signature.data.push(0);
        }

        if wrong_signature {
            signature = signer.sign("different payload".as_bytes()).unwrap();
        }

        let verifier = Secp256k1Verifier {};
        let result = verifier.verify(&verifying_key, msg.as_bytes(), &signature.data);
        assert!(result.is_err());
    }
}
