//! Cryptographic signatures.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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
    /// Sets a signer for the given algorithm.
    pub fn set_signer(&mut self, alg: SignatureAlgId, signer: Box<dyn Signer + Send + Sync>) {
        self.signers.insert(alg, signer);
    }

    /// Configures a secp256k1 signer with the provided signing key.
    pub fn set_secp256k1(&mut self, key: &[u8]) -> Result<&mut Self, SignerError> {
        self.set_signer(
            SignatureAlgId::SECP256K1,
            Box::new(Secp256k1Signer::new(key)?),
        );

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
    /// Signs the message.
    fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError>;
}

/// Provider of signature verifiers.
pub struct SignatureVerifierProvider {
    verifiers: HashMap<SignatureAlgId, Box<dyn SignatureVerifier + Send + Sync>>,
}

impl Default for SignatureVerifierProvider {
    fn default() -> Self {
        let mut verifiers = HashMap::new();

        verifiers.insert(SignatureAlgId::SECP256K1, Box::new(Secp256k1Verifier) as _);

        Self { verifiers }
    }
}

impl SignatureVerifierProvider {
    /// Sets a verifier for the given algorithm.
    pub fn set_verifier(
        &mut self,
        alg: SignatureAlgId,
        verifier: Box<dyn SignatureVerifier + Send + Sync>,
    ) {
        self.verifiers.insert(alg, verifier);
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
    /// Verifies the signature.
    fn verify(&self, key: &VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError>;
}

/// Verifying key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyingKey {
    /// The key algorithm.
    pub alg: KeyAlgId,
    /// The key data.
    pub data: Vec<u8>,
}

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
        fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
            let sig: Secp256K1Signature = self.0.lock().unwrap().sign(msg);

            Ok(Signature {
                alg: SignatureAlgId::SECP256K1,
                data: sig.to_vec(),
            })
        }
    }

    /// secp256k1 verifier.
    pub struct Secp256k1Verifier;

    impl SignatureVerifier for Secp256k1Verifier {
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
