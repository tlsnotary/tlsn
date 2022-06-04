use async_trait::async_trait;
use tls_core::msgs::message::{OpaqueMessage, PlainMessage};

/// Objects with this trait can decrypt TLS messages.
#[async_trait]
pub trait MessageDecrypter: Send + Sync {
    type Error;
    /// Perform the decryption over the concerned TLS message.
    async fn decrypt(&self, m: OpaqueMessage, seq: u64) -> Result<PlainMessage, Self::Error>;
}

/// Objects with this trait can encrypt TLS messages.
#[async_trait]
pub trait MessageEncrypter: Send + Sync {
    type Error: Sized;
    /// Perform the encryption over the concerned TLS message.
    async fn encrypt(&self, m: PlainMessage, seq: u64) -> Result<OpaqueMessage, Self::Error>;
}