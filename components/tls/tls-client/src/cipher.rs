use crate::Error;
use async_trait::async_trait;
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
