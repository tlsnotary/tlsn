mod standard;

use crate::Error;
use tls_core::msgs::enums::ProtocolVersion;
use tls_core::msgs::handshake::Random;
use tls_core::msgs::message::{OpaqueMessage, PlainMessage};
use tls_core::{key::PublicKey, suites::SupportedCipherSuite};

use async_trait::async_trait;

pub(crate) use standard::StandardCrypto;

/// Encryption modes for Crypto implementor
#[derive(Debug, Clone)]
pub enum EncryptMode {
    /// Encrypt payload with PSK
    EarlyData,
    /// Encrypt payload with Handshake keys
    Handshake,
    /// Encrypt payload with Application traffic keys
    Application,
}

/// Decryption modes for Crypto implementor
#[derive(Debug, Clone)]
pub enum DecryptMode {
    /// Decrypt payload with Handshake keys
    Handshake,
    /// Decrypt payload with Application traffic keys
    Application,
}

/// Core trait which manages crypto operations for the TLS connection such as key exchange, encryption
/// and decryption.
#[async_trait]
pub trait Crypto: Send {
    /// Signals selected protocol version to implementor.
    /// Throws error if version is not supported.
    fn select_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), Error>;
    /// Signals selected cipher suite to implementor.
    /// Throws error if cipher suite is not supported.
    fn select_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), Error>;
    /// Returns configured cipher suite.
    fn suite(&self) -> Result<SupportedCipherSuite, Error>;
    /// Set encryption mode
    fn set_encrypt(&mut self, mode: EncryptMode) -> Result<(), Error>;
    /// Set decryption mode
    fn set_decrypt(&mut self, mode: DecryptMode) -> Result<(), Error>;
    /// Returns client_random value.
    async fn client_random(&mut self) -> Result<Random, Error>;
    /// Returns public client keyshare.
    async fn client_key_share(&mut self) -> Result<PublicKey, Error>;
    /// Sets server random.
    async fn set_server_random(&mut self, random: Random) -> Result<(), Error>;
    /// Sets server keyshare.
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), Error>;
    /// Sets handshake hash at ClientKeyExchange for EMS.
    async fn set_hs_hash_client_key_exchange(&mut self, hash: &[u8]) -> Result<(), Error>;
    /// Sets handshake hash at ServerHello.
    async fn set_hs_hash_server_hello(&mut self, hash: &[u8]) -> Result<(), Error>;
    /// Returns expected ServerFinished verify_data.
    async fn server_finished(&mut self, hash: &[u8]) -> Result<Vec<u8>, Error>;
    /// Returns ClientFinished verify_data.
    async fn client_finished(&mut self, hash: &[u8]) -> Result<Vec<u8>, Error>;
    /// Perform the encryption over the concerned TLS message.
    async fn encrypt(&mut self, m: PlainMessage, seq: u64) -> Result<OpaqueMessage, Error>;
    /// Perform the decryption over the concerned TLS message.
    async fn decrypt(&mut self, m: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error>;
}

pub struct InvalidCrypto {}

#[async_trait]
impl Crypto for InvalidCrypto {
    fn select_protocol_version(&mut self, _version: ProtocolVersion) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    fn select_cipher_suite(&mut self, _suite: SupportedCipherSuite) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    fn suite(&self) -> Result<SupportedCipherSuite, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    /// Start encryption
    fn set_encrypt(&mut self, _mode: EncryptMode) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    /// Start decryption
    fn set_decrypt(&mut self, _mode: DecryptMode) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn client_random(&mut self) -> Result<Random, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn client_key_share(&mut self) -> Result<PublicKey, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn set_server_random(&mut self, _random: Random) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn set_server_key_share(&mut self, _key: PublicKey) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn set_hs_hash_client_key_exchange(&mut self, _hash: &[u8]) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn set_hs_hash_server_hello(&mut self, _hash: &[u8]) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn server_finished(&mut self, _hash: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn client_finished(&mut self, _hash: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn encrypt(&mut self, _m: PlainMessage, _seq: u64) -> Result<OpaqueMessage, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn decrypt(&mut self, _m: OpaqueMessage, _seq: u64) -> Result<PlainMessage, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
}
