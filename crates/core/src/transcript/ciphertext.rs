//! Ciphertext commitments and proof.

use crate::{
    hash::{Blinder, HashAlgId, HashProviderError, TypedHash},
    transcript::{hash::hash_plaintext, CiphertextTranscript, Direction, Idx, Transcript},
    CryptoProvider,
};
use serde::{Deserialize, Serialize};

/// Ciphertext commitment.
///
/// Also contains a commitment to the client or sever write key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CiphertextCommitment {
    /// Indices for this commitment.
    pub idx: Idx,
    /// The transcript of the ciphertext.
    pub transcript: CiphertextTranscript,
    /// Hash of key and iv.
    pub key_iv_hash: TypedHash,
}

/// Proof for a [`Ciphertext`] commitment.
#[derive(Clone, Serialize, Deserialize)]
pub struct PlaintextProof {
    /// The plaintext.
    pub plaintext: Vec<u8>,
    /// The corresponding indices.
    pub idx: Idx,
    /// Secret of the session.
    pub secret: SessionSecret,
}

impl PlaintextProof {
    /// Creates a new proof.
    ///
    /// # Arguments
    ///
    /// * `transcript` - The TLS transcript.
    /// * `secret` - The session secret.
    pub fn new(transcript: &Transcript, secret: SessionSecret) -> Self {
        let plaintext = transcript.received.clone();
        let len = transcript.len_of_direction(Direction::Received);
        let idx = Idx::new(0..len);

        PlaintextProof {
            plaintext,
            idx,
            secret,
        }
    }

    /// Verifies the plaintext proof.
    ///
    /// Returns the authed indices.
    ///
    /// # Arguments
    ///
    /// * `provider` - Provider for the hash algorithm used.
    /// * `commitments` - Commitments to verify with this proof.
    pub fn verify_with_provider(
        self,
        provider: &CryptoProvider,
        commitment: CiphertextCommitment,
    ) -> Result<Idx, PlaintextProofError> {
        // TODO: Reconstruct ciphertext from plaintext. Need iv, explicit_nonce, counters...

        if self.secret.alg != HashAlgId::SHA256 {
            return Err(PlaintextProofError::new(
                ErrorKind::Proof,
                format!(
                    "unsupported hash algorithm: {}, only SHA256 is currently supported",
                    self.secret.alg
                ),
            ));
        }
        let hasher = provider.hash.get(&self.secret.alg)?;
        let key = self.secret.key.key;
        let iv = self.secret.key.iv;
        let blinder = self.secret.blinder;
        let plaintext = self.plaintext;
        let explicit_nonces = &commitment.transcript.explicit_nonces;

        let mut key_and_iv = [0_u8; 20];
        key_and_iv[0..16].copy_from_slice(&key);
        key_and_iv[16..20].copy_from_slice(&iv);

        let key_iv_hash = hash_plaintext(hasher, &key_and_iv, &blinder);

        let mut ciphertext = Vec::with_capacity(commitment.transcript.ciphertext.len());

        for (explicit_nonce, plain_block) in explicit_nonces.iter().zip(plaintext.chunks(16)) {
            let explicit_nonce: [u8; 8] = explicit_nonce
                .as_slice()
                .try_into()
                .expect("explicit nonce should be 8 bytes");
            let cipherblock = apply_keystream(&key, &iv, &explicit_nonce, plain_block)?;

            ciphertext.push(cipherblock);
        }

        let transcript = CiphertextTranscript {
            direction: Direction::Received,
            explicit_nonces: explicit_nonces.clone(),
            ciphertext,
        };
        let expected = CiphertextCommitment {
            idx: self.idx,
            transcript,
            key_iv_hash,
        };

        if expected != commitment {
            return Err(PlaintextProofError::new(
                ErrorKind::Proof,
                "Proof does not match any commitment",
            ));
        }
        let idx = commitment.idx.clone();

        Ok(idx)
    }
}

fn apply_keystream(
    key: &[u8; 16],
    iv: &[u8; 4],
    explicit_nonce: &[u8; 8],
    input: &[u8],
) -> Result<Vec<u8>, PlaintextProofError> {
    use aes::Aes128;
    use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use ctr::Ctr32BE;

    const START_CTR: usize = 2;

    let mut full_iv = [0u8; 16];
    full_iv[0..4].copy_from_slice(iv);
    full_iv[4..12].copy_from_slice(explicit_nonce);

    let mut cipher = Ctr32BE::<Aes128>::new(key.into(), &full_iv.into());
    let mut output = input.to_vec();

    cipher
        .try_seek(START_CTR * 16)
        .expect("start counter is less than keystream length");
    cipher.apply_keystream(&mut output);

    Ok(output)
}

/// TLS session secret.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct SessionSecret {
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// The session key.
    pub key: SessionKey,
    /// Blinder for the key.
    pub blinder: Blinder,
}

opaque_debug::implement!(SessionSecret);

/// The session key.
///
/// Contains the session key (either client write key or server write key) and corresponding iv.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct SessionKey {
    /// The key.
    pub key: [u8; 16],
    /// The iv.
    pub iv: [u8; 4],
}

opaque_debug::implement!(SessionKey);

/// Error for [`PlaintextProof`].
#[derive(Debug, thiserror::Error)]
pub struct PlaintextProofError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl PlaintextProofError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Provider,
    Proof,
}

impl std::fmt::Display for PlaintextProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("encoding proof error: ")?;

        match self.kind {
            ErrorKind::Provider => f.write_str("provider error")?,
            ErrorKind::Proof => f.write_str("proof error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

impl From<HashProviderError> for PlaintextProofError {
    fn from(error: HashProviderError) -> Self {
        Self::new(ErrorKind::Provider, error)
    }
}
