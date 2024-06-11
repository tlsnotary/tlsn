use crate::Error;
use async_trait::async_trait;
use ring::{aead, hkdf};
use tls_core::msgs::{
    codec,
    message::{OpaqueMessage, PlainMessage},
};

/// Objects with this trait can decrypt TLS messages.
#[async_trait]
pub trait MessageDecrypter: Send + Sync {
    /// Perform the decryption over the concerned TLS message.
    async fn decrypt(&self, m: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error>;
}

/// Objects with this trait can encrypt TLS messages.
#[async_trait]
pub trait MessageEncrypter: Send + Sync {
    /// Perform the encryption over the concerned TLS message.
    async fn encrypt(&self, m: PlainMessage, seq: u64) -> Result<OpaqueMessage, Error>;
}

/// A `MessageEncrypter` which doesn't work.
pub struct InvalidMessageEncrypter {}

#[async_trait]
impl MessageEncrypter for InvalidMessageEncrypter {
    async fn encrypt(&self, _m: PlainMessage, _seq: u64) -> Result<OpaqueMessage, Error> {
        Err(Error::EncryptError)
    }
}

/// A `MessageDecrypter` which doesn't work.
pub struct InvalidMessageDecrypter {}

#[async_trait]
impl MessageDecrypter for InvalidMessageDecrypter {
    async fn decrypt(&self, _m: OpaqueMessage, _seq: u64) -> Result<PlainMessage, Error> {
        Err(Error::DecryptError)
    }
}

/// A write or read IV.
#[derive(Default)]
pub(crate) struct Iv(pub(crate) [u8; aead::NONCE_LEN]);

impl Iv {
    #[cfg(feature = "tls12")]
    fn new(value: [u8; aead::NONCE_LEN]) -> Self {
        Self(value)
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn copy(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), aead::NONCE_LEN);
        let mut iv = Self::new(Default::default());
        iv.0.copy_from_slice(value);
        iv
    }

    #[cfg(test)]
    pub(crate) fn value(&self) -> &[u8; 12] {
        &self.0
    }
}

pub(crate) struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Self(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
    }
}

pub(crate) fn make_nonce(iv: &Iv, seq: u64) -> aead::Nonce {
    let mut nonce = [0u8; aead::NONCE_LEN];
    codec::put_u64(seq, &mut nonce[4..]);

    nonce.iter_mut().zip(iv.0.iter()).for_each(|(nonce, iv)| {
        *nonce ^= *iv;
    });

    aead::Nonce::assume_unique_for_key(nonce)
}
