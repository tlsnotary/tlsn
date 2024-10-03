//! TLS connection types.
//!
//! ## Commitment
//!
//! During the TLS handshake the Notary receives the Server's ephemeral public
//! key, and this key serves as a binding commitment to the identity of the
//! Server. The ephemeral key itself does not reveal the Server's identity, but
//! it is bound to it via a signature created using the Server's
//! X.509 certificate.
//!
//! A Prover can withhold the Server's signature and certificate chain from the
//! Notary to improve privacy and censorship resistance.
//!
//! ## Proving the Server's identity
//!
//! A Prover can prove the Server's identity to a Verifier by sending a
//! [`ServerIdentityProof`]. This proof contains all the information required to
//! establish the link between the TLS connection and the Server's X.509
//! certificate. A Verifier checks the Server's certificate against their own
//! trust anchors, the same way a typical TLS client would.

mod commit;
mod proof;

use std::fmt;

use serde::{Deserialize, Serialize};
use tls_core::{
    msgs::{
        codec::Codec,
        enums::NamedGroup,
        handshake::{DigitallySignedStruct, ServerECDHParams},
    },
    verify::ServerCertVerifier as _,
};
use web_time::{Duration, UNIX_EPOCH};

use crate::{hash::impl_domain_separator, CryptoProvider};

pub use commit::{ServerCertCommitment, ServerCertOpening};
pub use proof::{ServerIdentityProof, ServerIdentityProofError};

/// TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    /// TLS 1.2.
    V1_2,
    /// TLS 1.3.
    V1_3,
}

impl TryFrom<tls_core::msgs::enums::ProtocolVersion> for TlsVersion {
    type Error = &'static str;

    fn try_from(value: tls_core::msgs::enums::ProtocolVersion) -> Result<Self, Self::Error> {
        Ok(match value {
            tls_core::msgs::enums::ProtocolVersion::TLSv1_2 => TlsVersion::V1_2,
            tls_core::msgs::enums::ProtocolVersion::TLSv1_3 => TlsVersion::V1_3,
            _ => return Err("unsupported TLS version"),
        })
    }
}

/// Server's name, a.k.a. the DNS name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerName(String);

impl ServerName {
    /// Creates a new server name.
    pub fn new(name: String) -> Self {
        Self(name)
    }

    /// Returns the name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ServerName {
    fn from(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl AsRef<str> for ServerName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type of a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum KeyType {
    /// secp256r1.
    SECP256R1 = 0x0017,
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

impl TryFrom<tls_core::msgs::enums::SignatureScheme> for SignatureScheme {
    type Error = &'static str;

    fn try_from(value: tls_core::msgs::enums::SignatureScheme) -> Result<Self, Self::Error> {
        use tls_core::msgs::enums::SignatureScheme as Core;
        use SignatureScheme::*;
        Ok(match value {
            Core::RSA_PKCS1_SHA1 => RSA_PKCS1_SHA1,
            Core::ECDSA_SHA1_Legacy => ECDSA_SHA1_Legacy,
            Core::RSA_PKCS1_SHA256 => RSA_PKCS1_SHA256,
            Core::ECDSA_NISTP256_SHA256 => ECDSA_NISTP256_SHA256,
            Core::RSA_PKCS1_SHA384 => RSA_PKCS1_SHA384,
            Core::ECDSA_NISTP384_SHA384 => ECDSA_NISTP384_SHA384,
            Core::RSA_PKCS1_SHA512 => RSA_PKCS1_SHA512,
            Core::ECDSA_NISTP521_SHA512 => ECDSA_NISTP521_SHA512,
            Core::RSA_PSS_SHA256 => RSA_PSS_SHA256,
            Core::RSA_PSS_SHA384 => RSA_PSS_SHA384,
            Core::RSA_PSS_SHA512 => RSA_PSS_SHA512,
            Core::ED25519 => ED25519,
            _ => return Err("unsupported signature scheme"),
        })
    }
}

impl From<SignatureScheme> for tls_core::msgs::enums::SignatureScheme {
    fn from(value: SignatureScheme) -> Self {
        use tls_core::msgs::enums::SignatureScheme::*;
        match value {
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

/// X.509 certificate, DER encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate(pub Vec<u8>);

impl From<tls_core::key::Certificate> for Certificate {
    fn from(cert: tls_core::key::Certificate) -> Self {
        Self(cert.0)
    }
}

/// Server's signature of the key exchange parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSignature {
    /// Signature scheme.
    pub scheme: SignatureScheme,
    /// Signature data.
    pub sig: Vec<u8>,
}

/// Server's ephemeral public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEphemKey {
    /// Type of the public key.
    #[serde(rename = "type")]
    pub typ: KeyType,
    /// Public key data.
    pub key: Vec<u8>,
}

impl_domain_separator!(ServerEphemKey);

impl ServerEphemKey {
    /// Encodes the key exchange parameters as in TLS.
    pub(crate) fn kx_params(&self) -> Vec<u8> {
        let group = match self.typ {
            KeyType::SECP256R1 => NamedGroup::secp256r1,
        };

        let mut kx_params = Vec::new();
        ServerECDHParams::new(group, &self.key).encode(&mut kx_params);

        kx_params
    }
}

impl TryFrom<tls_core::key::PublicKey> for ServerEphemKey {
    type Error = &'static str;

    fn try_from(value: tls_core::key::PublicKey) -> Result<Self, Self::Error> {
        let tls_core::msgs::enums::NamedGroup::secp256r1 = value.group else {
            return Err("unsupported key type");
        };

        Ok(ServerEphemKey {
            typ: KeyType::SECP256R1,
            key: value.key,
        })
    }
}

/// TLS session information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// UNIX time when the TLS connection started.
    pub time: u64,
    /// TLS version used in the connection.
    pub version: TlsVersion,
    /// Transcript length.
    pub transcript_length: TranscriptLength,
}

impl_domain_separator!(ConnectionInfo);

/// Transcript length information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptLength {
    /// Number of bytes sent by the Prover to the Server.
    pub sent: u32,
    /// Number of bytes received by the Prover from the Server.
    pub received: u32,
}

/// TLS 1.2 handshake data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeDataV1_2 {
    /// Client random.
    pub client_random: [u8; 32],
    /// Server random.
    pub server_random: [u8; 32],
    /// Server's ephemeral public key.
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

impl_domain_separator!(HandshakeData);

/// Server certificate and handshake data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCertData {
    /// Certificate chain.
    pub certs: Vec<Certificate>,
    /// Server signature of the key exchange parameters.
    pub sig: ServerSignature,
    /// TLS handshake data.
    pub handshake: HandshakeData,
}

impl ServerCertData {
    /// Verifies the server certificate data.
    ///
    /// # Arguments
    ///
    /// * `provider` - The crypto provider to use for verification.
    /// * `time` - The time of the connection.
    /// * `server_ephemeral_key` - The server's ephemeral key.
    /// * `server_name` - The server name.
    pub fn verify_with_provider(
        &self,
        provider: &CryptoProvider,
        time: u64,
        server_ephemeral_key: &ServerEphemKey,
        server_name: &ServerName,
    ) -> Result<(), CertificateVerificationError> {
        #[allow(irrefutable_let_patterns)]
        let HandshakeData::V1_2(HandshakeDataV1_2 {
            client_random,
            server_random,
            server_ephemeral_key: expected_server_ephemeral_key,
        }) = &self.handshake
        else {
            unreachable!("only TLS 1.2 is implemented")
        };

        if server_ephemeral_key != expected_server_ephemeral_key {
            return Err(CertificateVerificationError::InvalidServerEphemeralKey);
        }

        // Verify server name
        let server_name = tls_core::dns::ServerName::try_from(server_name.as_ref())
            .map_err(|_| CertificateVerificationError::InvalidIdentity(server_name.clone()))?;

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
        provider
            .cert
            .verify_server_cert(
                end_entity,
                intermediates,
                &server_name,
                &mut [].into_iter(),
                &[],
                UNIX_EPOCH + Duration::from_secs(time),
            )
            .map_err(|_| CertificateVerificationError::InvalidCert)?;

        // Verify the signature matches the certificate and key exchange parameters.
        let mut message = Vec::new();
        message.extend_from_slice(client_random);
        message.extend_from_slice(server_random);
        message.extend_from_slice(&server_ephemeral_key.kx_params());

        let dss = DigitallySignedStruct::new(self.sig.scheme.into(), self.sig.sig.clone());

        provider
            .cert
            .verify_tls12_signature(&message, end_entity, &dss)
            .map_err(|_| CertificateVerificationError::InvalidServerSignature)?;

        Ok(())
    }
}

/// Errors that can occur when verifying a certificate chain or signature.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum CertificateVerificationError {
    #[error("invalid server identity: {0}")]
    InvalidIdentity(ServerName),
    #[error("missing server certificates")]
    MissingCerts,
    #[error("invalid server certificate")]
    InvalidCert,
    #[error("invalid server signature")]
    InvalidServerSignature,
    #[error("invalid server ephemeral key")]
    InvalidServerEphemeralKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixtures::ConnectionFixture, transcript::Transcript};

    use hex::FromHex;
    use rstest::*;
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

    #[fixture]
    #[once]
    fn crypto_provider() -> CryptoProvider {
        CryptoProvider::default()
    }

    fn tlsnotary() -> ConnectionFixture {
        ConnectionFixture::tlsnotary(Transcript::new(GET_WITH_HEADER, OK_JSON).length())
    }

    fn appliedzkp() -> ConnectionFixture {
        ConnectionFixture::appliedzkp(Transcript::new(GET_WITH_HEADER, OK_JSON).length())
    }

    /// Expect chain verification to succeed.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_sucess_ca_implicit(
        crypto_provider: &CryptoProvider,
        #[case] mut data: ConnectionFixture,
    ) {
        // Remove the CA cert
        data.server_cert_data.certs.pop();

        assert!(data
            .server_cert_data
            .verify_with_provider(
                crypto_provider,
                data.connection_info.time,
                data.server_ephemeral_key(),
                &ServerName::from(data.server_name.as_ref()),
            )
            .is_ok());
    }

    /// Expect chain verification to succeed even when a trusted CA is provided
    /// among the intermediate certs. webpki handles such cases properly.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_success_ca_explicit(
        crypto_provider: &CryptoProvider,
        #[case] data: ConnectionFixture,
    ) {
        assert!(data
            .server_cert_data
            .verify_with_provider(
                crypto_provider,
                data.connection_info.time,
                data.server_ephemeral_key(),
                &ServerName::from(data.server_name.as_ref()),
            )
            .is_ok());
    }

    /// Expect to fail since the end entity cert was not valid at the time.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_bad_time(
        crypto_provider: &CryptoProvider,
        #[case] data: ConnectionFixture,
    ) {
        // unix time when the cert chain was NOT valid
        let bad_time: u64 = 1571465711;

        let err = data.server_cert_data.verify_with_provider(
            crypto_provider,
            bad_time,
            data.server_ephemeral_key(),
            &ServerName::from(data.server_name.as_ref()),
        );

        assert!(matches!(
            err.unwrap_err(),
            CertificateVerificationError::InvalidCert
        ));
    }

    /// Expect to fail when no intermediate cert provided.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_no_interm_cert(
        crypto_provider: &CryptoProvider,
        #[case] mut data: ConnectionFixture,
    ) {
        // Remove the CA cert
        data.server_cert_data.certs.pop();
        // Remove the intermediate cert
        data.server_cert_data.certs.pop();

        let err = data.server_cert_data.verify_with_provider(
            crypto_provider,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &ServerName::from(data.server_name.as_ref()),
        );

        assert!(matches!(
            err.unwrap_err(),
            CertificateVerificationError::InvalidCert
        ));
    }

    /// Expect to fail when no intermediate cert provided even if a trusted CA
    /// cert is provided.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_no_interm_cert_with_ca_cert(
        crypto_provider: &CryptoProvider,
        #[case] mut data: ConnectionFixture,
    ) {
        // Remove the intermediate cert
        data.server_cert_data.certs.remove(1);

        let err = data.server_cert_data.verify_with_provider(
            crypto_provider,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &ServerName::from(data.server_name.as_ref()),
        );

        assert!(matches!(
            err.unwrap_err(),
            CertificateVerificationError::InvalidCert
        ));
    }

    /// Expect to fail because end-entity cert is wrong.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_bad_ee_cert(
        crypto_provider: &CryptoProvider,
        #[case] mut data: ConnectionFixture,
    ) {
        let ee: &[u8] = include_bytes!("./fixtures/data/unknown/ee.der");

        // Change the end entity cert
        data.server_cert_data.certs[0] = Certificate(ee.to_vec());

        let err = data.server_cert_data.verify_with_provider(
            crypto_provider,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &ServerName::from(data.server_name.as_ref()),
        );

        assert!(matches!(
            err.unwrap_err(),
            CertificateVerificationError::InvalidCert
        ));
    }

    /// Expect sig verification to fail because client_random is wrong.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_sig_ke_params_fail_bad_client_random(
        crypto_provider: &CryptoProvider,
        #[case] mut data: ConnectionFixture,
    ) {
        let HandshakeData::V1_2(HandshakeDataV1_2 { client_random, .. }) =
            &mut data.server_cert_data.handshake;
        client_random[31] = client_random[31].wrapping_add(1);

        let err = data.server_cert_data.verify_with_provider(
            crypto_provider,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &ServerName::from(data.server_name.as_ref()),
        );

        assert!(matches!(
            err.unwrap_err(),
            CertificateVerificationError::InvalidServerSignature
        ));
    }

    /// Expect sig verification to fail because the sig is wrong.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_sig_ke_params_fail_bad_sig(
        crypto_provider: &CryptoProvider,
        #[case] mut data: ConnectionFixture,
    ) {
        data.server_cert_data.sig.sig[31] = data.server_cert_data.sig.sig[31].wrapping_add(1);

        let err = data.server_cert_data.verify_with_provider(
            crypto_provider,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &ServerName::from(data.server_name.as_ref()),
        );

        assert!(matches!(
            err.unwrap_err(),
            CertificateVerificationError::InvalidServerSignature
        ));
    }

    /// Expect to fail because the dns name is not in the cert.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_check_dns_name_present_in_cert_fail_bad_host(
        crypto_provider: &CryptoProvider,
        #[case] data: ConnectionFixture,
    ) {
        let bad_name = ServerName::from("badhost.com");

        let err = data.server_cert_data.verify_with_provider(
            crypto_provider,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &bad_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            CertificateVerificationError::InvalidCert
        ));
    }

    /// Expect to fail because the ephemeral key provided is wrong.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_invalid_ephemeral_key(
        crypto_provider: &CryptoProvider,
        #[case] data: ConnectionFixture,
    ) {
        let wrong_ephemeral_key = ServerEphemKey {
            typ: KeyType::SECP256R1,
            key: Vec::<u8>::from_hex(include_bytes!("./fixtures/data/unknown/pubkey")).unwrap(),
        };

        let err = data.server_cert_data.verify_with_provider(
            crypto_provider,
            data.connection_info.time,
            &wrong_ephemeral_key,
            &ServerName::from(data.server_name.as_ref()),
        );

        assert!(matches!(
            err.unwrap_err(),
            CertificateVerificationError::InvalidServerEphemeralKey
        ));
    }

    /// Expect to fail when no cert provided.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_no_cert(
        crypto_provider: &CryptoProvider,
        #[case] mut data: ConnectionFixture,
    ) {
        // Empty certs
        data.server_cert_data.certs = Vec::new();

        let err = data.server_cert_data.verify_with_provider(
            crypto_provider,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &ServerName::from(data.server_name.as_ref()),
        );

        assert!(matches!(
            err.unwrap_err(),
            CertificateVerificationError::MissingCerts
        ));
    }
}
