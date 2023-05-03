use async_trait::async_trait;
use tls_core::{
    key::PublicKey,
    msgs::{
        enums::{CipherSuite, NamedGroup, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BackendError {
    #[error("Invalid state: {0:?}")]
    InvalidState(String),
    #[error("Unsupported protocol version: {0:?}")]
    UnsupportedProtocolVersion(ProtocolVersion),
    #[error("Unsupported ciphersuite: {0:?}")]
    UnsupportedCiphersuite(CipherSuite),
    #[error("Unsupported curve group: {0:?}")]
    UnsupportedCurveGroup(NamedGroup),
    #[error("Invalid configuration: {0:?}")]
    InvalidConfig(String),
    #[error("Invalid server public keyshare")]
    InvalidServerKey,
    #[error("Encryption error: {0:?}")]
    EncryptionError(String),
    #[error("Decryption error: {0:?}")]
    DecryptionError(String),
}

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
pub trait Backend: Send {
    /// Signals selected protocol version to implementor.
    /// Throws error if version is not supported.
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError>;
    /// Signals selected cipher suite to implementor.
    /// Throws error if cipher suite is not supported.
    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError>;
    /// Returns configured cipher suite.
    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError>;
    /// Set encryption mode
    async fn set_encrypt(&mut self, mode: EncryptMode) -> Result<(), BackendError>;
    /// Set decryption mode
    async fn set_decrypt(&mut self, mode: DecryptMode) -> Result<(), BackendError>;
    /// Returns client_random value.
    async fn get_client_random(&mut self) -> Result<Random, BackendError>;
    /// Returns public client keyshare.
    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError>;
    /// Sets server random.
    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError>;
    /// Sets server keyshare.
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError>;
    /// Sets handshake hash at ClientKeyExchange for EMS.
    async fn set_hs_hash_client_key_exchange(&mut self, hash: &[u8]) -> Result<(), BackendError>;
    /// Sets handshake hash at ServerHello.
    async fn set_hs_hash_server_hello(&mut self, hash: &[u8]) -> Result<(), BackendError>;
    /// Returns expected ServerFinished verify_data.
    async fn get_server_finished_vd(&mut self, hash: &[u8]) -> Result<Vec<u8>, BackendError>;
    /// Returns ClientFinished verify_data.
    async fn get_client_finished_vd(&mut self, hash: &[u8]) -> Result<Vec<u8>, BackendError>;
    /// Perform the encryption over the concerned TLS message.
    async fn encrypt(&mut self, msg: PlainMessage, seq: u64)
        -> Result<OpaqueMessage, BackendError>;
    /// Perform the decryption over the concerned TLS message.
    async fn decrypt(&mut self, msg: OpaqueMessage, seq: u64)
        -> Result<PlainMessage, BackendError>;
}
