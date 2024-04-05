//! TLS connection types.

mod proof;

use serde::{Deserialize, Serialize};
use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    msgs::{
        codec::Codec,
        enums::NamedGroup,
        handshake::{DigitallySignedStruct, ServerECDHParams},
    },
    verify::{ServerCertVerifier as _, WebPkiVerifier},
};
use web_time::{Duration, UNIX_EPOCH};

use crate::{
    hash::{Hash, HashAlgorithm},
    serialize::CanonicalSerialize,
};

pub use proof::{ServerIdentityProof, ServerIdentityProofError};

/// TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    /// TLS 1.2.
    V1_2 = 0x00,
    /// TLS 1.3.
    V1_3 = 0x01,
}

/// A Server's identity, a.k.a. the DNS name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ServerIdentity(String);

impl ServerIdentity {
    /// Creates a new server identity.
    pub fn new(name: String) -> Self {
        Self(name)
    }

    /// Returns the DNS name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ServerIdentity {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The type of a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum KeyType {
    /// secp256r1.
    Secp256r1 = 0x0017,
}

/// Signature scheme on the key exchange parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types, missing_docs)]
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

impl ServerEphemKey {
    /// Encodes the key exchange parameters as in TLS.
    pub(crate) fn kx_params(&self) -> Vec<u8> {
        let group = match self.typ {
            KeyType::Secp256r1 => NamedGroup::secp256r1,
        };

        let mut kx_params = Vec::new();
        ServerECDHParams::new(group, &self.key).encode(&mut kx_params);

        kx_params
    }
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
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HandshakeData {
    /// TLS 1.2 handshake data.
    V1_2(HandshakeDataV1_2),
}

/// Errors that can occur when verifying a certificate chain or signature.
#[derive(Debug, thiserror::Error)]
pub enum CertificateVerificationError {
    /// Invalid server identity.
    #[error("invalid server identity: {0:?}")]
    InvalidIdentity(ServerIdentity),
    /// Missing server certificates.
    #[error("missing server certificates")]
    MissingCerts,
    /// Invalid server certificate.
    #[error("invalid server certificate")]
    InvalidCert,
    /// Invalid server signature.
    #[error("invalid server signature")]
    InvalidServerSignature,
}

/// TLS certificate data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateData {
    /// The certificate chain.
    pub certs: Vec<Certificate>,
    /// The signature of the key exchange parameters.
    pub sig: ServerSignature,
}

impl CertificateData {
    /// Verifies the server identity with the default certificate root store
    /// provided by the `webpki-roots` crate.
    ///
    /// # Arguments
    ///
    /// * `info` - The connection information.
    /// * `handshake_data` - The handshake data.
    /// * `identity` - The server identity.
    pub fn verify(
        &self,
        info: &ConnectionInfo,
        handshake_data: &HandshakeData,
        identity: &ServerIdentity,
    ) -> Result<(), CertificateVerificationError> {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref(),
                ta.subject_public_key_info.as_ref(),
                ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
            )
        }));
        let cert_verifier = WebPkiVerifier::new(root_store, None);
        self.verify_with_verifier(info, handshake_data, identity, &cert_verifier)
    }

    /// Verifies the server identity proof certificate data.
    ///
    /// # Arguments
    ///
    /// * `info` - The connection information.
    /// * `handshake` - The handshake data.
    /// * `identity` - The server identity.
    /// * `cert_verifier` - The certificate verifier.
    pub fn verify_with_verifier(
        &self,
        info: &ConnectionInfo,
        handshake_data: &HandshakeData,
        identity: &ServerIdentity,
        cert_verifier: &WebPkiVerifier,
    ) -> Result<(), CertificateVerificationError> {
        #[allow(irrefutable_let_patterns)]
        let HandshakeData::V1_2(HandshakeDataV1_2 {
            client_random,
            server_random,
            server_ephemeral_key,
        }) = handshake_data
        else {
            unreachable!("only TLS 1.2 is implemented")
        };

        // Verify server name
        let server_name = tls_core::dns::ServerName::try_from(identity.as_ref())
            .map_err(|_| CertificateVerificationError::InvalidIdentity(identity.clone()))?;

        // Verify server certificate
        let cert_chain = self
            .certs
            .clone()
            .into_iter()
            .map(|cert| tls_core::key::Certificate(cert.0))
            .collect::<Vec<_>>();

        let (end_entity, intermediates) = cert_chain
            .split_first()
            .ok_or(CertificateVerificationError::MissingCerts)?;

        // Verify the end entity cert is valid for the provided server name
        // and that it chains to at least one of the roots we trust.
        _ = cert_verifier
            .verify_server_cert(
                end_entity,
                intermediates,
                &server_name,
                &mut [].into_iter(),
                &[],
                UNIX_EPOCH + Duration::from_secs(info.time),
            )
            .map_err(|_| CertificateVerificationError::InvalidCert)?;

        // Verify the signature matches the certificate and key exchange parameters.
        let mut message = Vec::new();
        message.extend_from_slice(client_random);
        message.extend_from_slice(server_random);
        message.extend_from_slice(&server_ephemeral_key.kx_params());

        let dss = DigitallySignedStruct::new(self.sig.scheme.to_tls_core(), self.sig.sig.clone());

        _ = cert_verifier
            .verify_tls12_signature(&message, end_entity, &dss)
            .map_err(|_| CertificateVerificationError::InvalidServerSignature)?;

        Ok(())
    }
}

/// TLS certificate secrets.
#[derive(Clone, Serialize, Deserialize)]
pub struct CertificateSecrets {
    /// The certificate data.
    pub data: CertificateData,
    /// The certificate nonce.
    pub cert_nonce: [u8; 16],
    /// The certificate chain nonce.
    pub chain_nonce: [u8; 16],
}

opaque_debug::implement!(CertificateSecrets);

impl CertificateSecrets {
    /// Computes the commitment to the certificate and signature, returning `None` if the certificate is missing.
    pub fn cert_commitment(&self, alg: HashAlgorithm) -> Option<Hash> {
        let end_entity = self.data.certs.first()?;
        let mut bytes = Vec::new();
        bytes.extend(CanonicalSerialize::serialize(end_entity));
        bytes.extend(CanonicalSerialize::serialize(&self.data.sig));
        bytes.extend_from_slice(&self.cert_nonce);
        Some(alg.hash(&bytes))
    }

    /// Computes the commitment to the certificate chain, returning `None` if the chain is missing.
    pub fn cert_chain_commitment(&self, alg: HashAlgorithm) -> Option<Hash> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.data.certs.len() as u32).to_le_bytes());
        for cert in &self.data.certs {
            bytes.extend(CanonicalSerialize::serialize(cert));
        }
        bytes.extend_from_slice(&self.chain_nonce);
        Some(alg.hash(&bytes))
    }
}

pub(crate) fn default_cert_verifier() -> WebPkiVerifier {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));
    WebPkiVerifier::new(root_store, None)
}
