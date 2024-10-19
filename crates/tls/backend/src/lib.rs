//! This library provides the [Backend] trait to encapsulate the cryptography
//! backend of the TLS client.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod notify;

pub use notify::{BackendNotifier, BackendNotify};

use async_trait::async_trait;
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        enums::{CipherSuite, NamedGroup, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};

/// Possible backend errors
#[allow(missing_docs)]
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
    #[error("internal error: {0:?}")]
    InternalError(String),
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

/// Core trait which manages crypto operations for the TLS connection such as
/// key exchange, encryption and decryption.
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
    /// Sets the server cert chain
    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), BackendError>;
    /// Sets the server kx details
    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError>;
    /// Sets handshake hash at ClientKeyExchange for EMS.
    async fn set_hs_hash_client_key_exchange(&mut self, hash: Vec<u8>) -> Result<(), BackendError>;
    /// Sets handshake hash at ServerHello.
    async fn set_hs_hash_server_hello(&mut self, hash: Vec<u8>) -> Result<(), BackendError>;
    /// Returns expected ServerFinished verify_data.
    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError>;
    /// Returns ClientFinished verify_data.
    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError>;
    /// Prepares the backend for encryption.
    async fn prepare_encryption(&mut self) -> Result<(), BackendError>;
    /// Perform the encryption over the concerned TLS message.
    async fn encrypt(&mut self, msg: PlainMessage, seq: u64)
        -> Result<OpaqueMessage, BackendError>;
    /// Perform the decryption over the concerned TLS message.
    async fn decrypt(&mut self, msg: OpaqueMessage, seq: u64)
        -> Result<PlainMessage, BackendError>;
    /// Buffer incoming message for decryption.
    async fn buffer_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError>;
    /// Returns next incoming message ready for decryption.
    async fn next_incoming(&mut self) -> Result<Option<OpaqueMessage>, BackendError>;
    /// Returns a notification future which resolves when the backend is ready
    /// to process the next message.
    async fn get_notify(&mut self) -> Result<BackendNotify, BackendError> {
        Ok(BackendNotify::dummy())
    }
    /// Returns the number of messages buffered for decryption.
    async fn buffer_len(&mut self) -> Result<usize, BackendError>;
    /// Signals to the backend that the server has closed the connection.
    async fn server_closed(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}
