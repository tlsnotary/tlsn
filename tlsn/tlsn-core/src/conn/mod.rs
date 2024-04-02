//! TLS connection types.

mod proof;

use serde::{Deserialize, Serialize};

pub use proof::ServerIdentityProof;

//pub use proof::{HandshakeProof, HandshakeProofError};

/// TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2.
    V1_2 = 0x00,
    /// TLS 1.3.
    V1_3 = 0x01,
}

/// A Server's identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ServerIdentity {
    /// A DNS name.
    Dns(String),
}

/// The type of a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyType {
    /// secp256r1.
    Secp256r1 = 0x0017,
}

/// Signature scheme on the key exchange parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum SignatureScheme {
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1Legacy = 0x0203,
    RsaPkcs1Sha256 = 0x0401,
    EcdsaNistp256Sha256 = 0x0403,
    RsaPkcs1Sha384 = 0x0501,
    EcdsaNistp384Sha384 = 0x0503,
    RsaPkcs1Sha512 = 0x0601,
    EcdsaNistp521Sha512 = 0x0603,
    RsaPssSha256 = 0x0804,
    RsaPssSha384 = 0x0805,
    RsaPssSha512 = 0x0806,
    Ed25519 = 0x0807,
}

impl SignatureScheme {
    pub(crate) fn to_tls_core(&self) -> tls_core::msgs::enums::SignatureScheme {
        use tls_core::msgs::enums::SignatureScheme::*;
        match self {
            SignatureScheme::RsaPkcs1Sha1 => RSA_PKCS1_SHA1,
            SignatureScheme::EcdsaSha1Legacy => ECDSA_SHA1_Legacy,
            SignatureScheme::RsaPkcs1Sha256 => RSA_PKCS1_SHA256,
            SignatureScheme::EcdsaNistp256Sha256 => ECDSA_NISTP256_SHA256,
            SignatureScheme::RsaPkcs1Sha384 => RSA_PKCS1_SHA384,
            SignatureScheme::EcdsaNistp384Sha384 => ECDSA_NISTP384_SHA384,
            SignatureScheme::RsaPkcs1Sha512 => RSA_PKCS1_SHA512,
            SignatureScheme::EcdsaNistp521Sha512 => ECDSA_NISTP521_SHA512,
            SignatureScheme::RsaPssSha256 => RSA_PSS_SHA256,
            SignatureScheme::RsaPssSha384 => RSA_PSS_SHA384,
            SignatureScheme::RsaPssSha512 => RSA_PSS_SHA512,
            SignatureScheme::Ed25519 => ED25519,
        }
    }
}

/// A X.509 certificate, DER encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate(pub Vec<u8>);

/// A server's signature of the key exchange parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSignature {
    /// The signature scheme.
    pub scheme: SignatureScheme,
    /// The signature bytes.
    pub sig: Vec<u8>,
}

/// A server's ephemeral public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEphemKey {
    /// The type of the public key.
    #[serde(rename = "type")]
    pub typ: KeyType,
    /// The public key bytes.
    pub key: Vec<u8>,
}

/// TLS session information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// The UNIX time when the TLS connection started.
    pub time: u64,
    /// The TLS version used in the connection.
    pub version: TlsVersion,
    /// Transcript length.
    pub transcript_length: TranscriptLength,
}

/// Transcript length information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptLength {
    /// The number of bytes sent by the Prover to the Server.
    pub sent: u32,
    /// The number of bytes received by the Prover from the Server.
    pub received: u32,
}

/// TLS 1.2 handshake data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeDataV1_2 {
    /// Client random.
    pub client_random: [u8; 32],
    /// Server random.
    pub server_random: [u8; 32],
    /// The server's ephemeral public key.
    pub server_ephemeral_key: ServerEphemKey,
}

/// TLS handshake data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HandshakeData {
    /// TLS 1.2 handshake data.
    V1_2(HandshakeDataV1_2),
}
