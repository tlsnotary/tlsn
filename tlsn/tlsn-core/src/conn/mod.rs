//! TLS connection types.

mod proof;

use serde::{Deserialize, Serialize};

pub use proof::ServerIdentityProof;

use crate::{
    hash::{Hash, HashAlgorithm},
    serialize::CanonicalSerialize,
};

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
#[allow(non_camel_case_types)]
pub enum SignatureScheme {
    RSA_PKCS1_SHA1 = 0x0201,
    ECDSA_SHA1_Legacy = 0x0203,
    RSA_PKCS1_SHA256 = 0x0401,
    ECDSA_NISTP256_SHA256 = 0x0403,
    RSA_PKCS1_SHA384 = 0x0501,
    ECDSA_NISTP384_SHA384 = 0x0503,
    RSA_PKCS1_SHA512 = 0x0601,
    ECDSA_NISTP521_SHA512 = 0x0603,
    RSA_PSS_SHA256 = 0x0804,
    RSA_PSS_SHA384 = 0x0805,
    RSA_PSS_SHA512 = 0x0806,
    ED25519 = 0x0807,
}

impl SignatureScheme {
    /// Converts a `u16` to a `SignatureScheme`.
    pub fn from_u16(value: u16) -> Option<Self> {
        use SignatureScheme::*;
        Some(match value {
            0x0201 => RSA_PKCS1_SHA1,
            0x0203 => ECDSA_SHA1_Legacy,
            0x0401 => RSA_PKCS1_SHA256,
            0x0403 => ECDSA_NISTP256_SHA256,
            0x0501 => RSA_PKCS1_SHA384,
            0x0503 => ECDSA_NISTP384_SHA384,
            0x0601 => RSA_PKCS1_SHA512,
            0x0603 => ECDSA_NISTP521_SHA512,
            0x0804 => RSA_PSS_SHA256,
            0x0805 => RSA_PSS_SHA384,
            0x0806 => RSA_PSS_SHA512,
            0x0807 => ED25519,
            _ => return None,
        })
    }

    pub(crate) fn to_tls_core(&self) -> tls_core::msgs::enums::SignatureScheme {
        use tls_core::msgs::enums::SignatureScheme::*;
        match self {
            SignatureScheme::RSA_PKCS1_SHA1 => RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy => ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256 => RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256 => ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384 => ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512 => ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => RSA_PSS_SHA512,
            SignatureScheme::ED25519 => ED25519,
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

/// TLS certificate data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateData {
    /// The certificate chain.
    pub certs: Vec<Certificate>,
    /// The signature of the key exchange parameters.
    pub sig: ServerSignature,
    /// The nonce which was hashed with the end-entity certificate and signature.
    pub cert_nonce: [u8; 16],
    /// The nonce which was hashed with the certificate chain.
    pub chain_nonce: [u8; 16],
}

impl CertificateData {
    /// Computes the commitment to the certificate and signature, returning `None` if the certificate is missing.
    pub fn cert_commitment(&self, alg: HashAlgorithm) -> Option<Hash> {
        let end_entity = self.certs.first()?;
        let mut bytes = Vec::new();
        bytes.extend(CanonicalSerialize::serialize(end_entity));
        bytes.extend(CanonicalSerialize::serialize(&self.sig));
        bytes.extend_from_slice(&self.cert_nonce);
        Some(alg.hash(&bytes))
    }

    /// Computes the commitment to the certificate chain, returning `None` if the chain is missing.
    pub fn cert_chain_commitment(&self, alg: HashAlgorithm) -> Option<Hash> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.certs.len() as u32).to_le_bytes());
        for cert in &self.certs {
            bytes.extend(CanonicalSerialize::serialize(cert));
        }
        bytes.extend_from_slice(&self.chain_nonce);
        Some(alg.hash(&bytes))
    }
}
