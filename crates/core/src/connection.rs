//! TLS connection types.

use std::fmt;

use rustls_pki_types as webpki_types;
use serde::{Deserialize, Serialize};
use tls_core::msgs::{codec::Codec, enums::NamedGroup, handshake::ServerECDHParams};

use crate::webpki::{CertificateDer, ServerCertVerifier, ServerCertVerifierError};

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

/// Server's name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServerName {
    /// DNS name.
    Dns(DnsName),
}

impl ServerName {
    pub(crate) fn to_webpki(&self) -> webpki_types::ServerName<'static> {
        match self {
            ServerName::Dns(name) => webpki_types::ServerName::DnsName(
                webpki_types::DnsName::try_from(name.0.as_str())
                    .expect("name was validated")
                    .to_owned(),
            ),
        }
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerName::Dns(name) => write!(f, "{name}"),
        }
    }
}

/// DNS name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct DnsName(String);

impl DnsName {
    /// Returns the DNS name as a string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for DnsName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Error returned when a DNS name is invalid.
#[derive(Debug, thiserror::Error)]
#[error("invalid DNS name")]
pub struct InvalidDnsNameError {}

impl TryFrom<&str> for DnsName {
    type Error = InvalidDnsNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // Borrow validation from rustls
        match webpki_types::DnsName::try_from_str(value) {
            Ok(_) => Ok(DnsName(value.to_string())),
            Err(_) => Err(InvalidDnsNameError {}),
        }
    }
}

impl TryFrom<String> for DnsName {
    type Error = InvalidDnsNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
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

/// Signature algorithm used on the key exchange parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types, missing_docs)]
pub enum SignatureAlgorithm {
    ECDSA_NISTP256_SHA256,
    ECDSA_NISTP256_SHA384,
    ECDSA_NISTP384_SHA256,
    ECDSA_NISTP384_SHA384,
    ED25519,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureAlgorithm::ECDSA_NISTP256_SHA256 => write!(f, "ECDSA_NISTP256_SHA256"),
            SignatureAlgorithm::ECDSA_NISTP256_SHA384 => write!(f, "ECDSA_NISTP256_SHA384"),
            SignatureAlgorithm::ECDSA_NISTP384_SHA256 => write!(f, "ECDSA_NISTP384_SHA256"),
            SignatureAlgorithm::ECDSA_NISTP384_SHA384 => write!(f, "ECDSA_NISTP384_SHA384"),
            SignatureAlgorithm::ED25519 => write!(f, "ED25519"),
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256 => {
                write!(f, "RSA_PKCS1_2048_8192_SHA256")
            }
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384 => {
                write!(f, "RSA_PKCS1_2048_8192_SHA384")
            }
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512 => {
                write!(f, "RSA_PKCS1_2048_8192_SHA512")
            }
            SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY => {
                write!(f, "RSA_PSS_2048_8192_SHA256_LEGACY_KEY")
            }
            SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY => {
                write!(f, "RSA_PSS_2048_8192_SHA384_LEGACY_KEY")
            }
            SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY => {
                write!(f, "RSA_PSS_2048_8192_SHA512_LEGACY_KEY")
            }
        }
    }
}

impl From<tls_core::verify::SignatureAlgorithm> for SignatureAlgorithm {
    fn from(value: tls_core::verify::SignatureAlgorithm) -> Self {
        use tls_core::verify::SignatureAlgorithm as Core;
        match value {
            Core::ECDSA_NISTP256_SHA256 => SignatureAlgorithm::ECDSA_NISTP256_SHA256,
            Core::ECDSA_NISTP256_SHA384 => SignatureAlgorithm::ECDSA_NISTP256_SHA384,
            Core::ECDSA_NISTP384_SHA256 => SignatureAlgorithm::ECDSA_NISTP384_SHA256,
            Core::ECDSA_NISTP384_SHA384 => SignatureAlgorithm::ECDSA_NISTP384_SHA384,
            Core::ED25519 => SignatureAlgorithm::ED25519,
            Core::RSA_PKCS1_2048_8192_SHA256 => SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256,
            Core::RSA_PKCS1_2048_8192_SHA384 => SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384,
            Core::RSA_PKCS1_2048_8192_SHA512 => SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512,
            Core::RSA_PSS_2048_8192_SHA256_LEGACY_KEY => {
                SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY
            }
            Core::RSA_PSS_2048_8192_SHA384_LEGACY_KEY => {
                SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY
            }
            Core::RSA_PSS_2048_8192_SHA512_LEGACY_KEY => {
                SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY
            }
        }
    }
}

/// Server's signature of the key exchange parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSignature {
    /// Signature algorithm.
    pub alg: SignatureAlgorithm,
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

/// Transcript length information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptLength {
    /// Number of bytes sent by the Prover to the Server.
    pub sent: u32,
    /// Number of bytes received by the Prover from the Server.
    pub received: u32,
}

/// TLS 1.2 certificate binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertBindingV1_2 {
    /// Client random.
    pub client_random: [u8; 32],
    /// Server random.
    pub server_random: [u8; 32],
    /// Server's ephemeral public key.
    pub server_ephemeral_key: ServerEphemKey,
}

/// TLS certificate binding.
///
/// This is the data that the server signs using its public key in the
/// certificate it presents during the TLS handshake. This provides a binding
/// between the server's identity and the ephemeral keys used to authenticate
/// the TLS session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertBinding {
    /// TLS 1.2 certificate binding.
    V1_2(CertBindingV1_2),
}

/// Verify data from the TLS handshake finished messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyData {
    /// Client finished verify data.
    pub client_finished: Vec<u8>,
    /// Server finished verify data.
    pub server_finished: Vec<u8>,
}

/// TLS handshake data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeData {
    /// Server certificate chain.
    pub certs: Vec<CertificateDer>,
    /// Server certificate signature over the binding message.
    pub sig: ServerSignature,
    /// Certificate binding.
    pub binding: CertBinding,
}

impl HandshakeData {
    /// Verifies the handshake data.
    ///
    /// # Arguments
    ///
    /// * `verifier` - Cerificate verifier.
    /// * `time` - The time of the connection.
    /// * `server_ephemeral_key` - The server's ephemeral key.
    /// * `server_name` - The server name.
    pub fn verify(
        &self,
        verifier: &ServerCertVerifier,
        time: u64,
        server_ephemeral_key: &ServerEphemKey,
        server_name: &ServerName,
    ) -> Result<(), HandshakeVerificationError> {
        #[allow(irrefutable_let_patterns)]
        let CertBinding::V1_2(CertBindingV1_2 {
            client_random,
            server_random,
            server_ephemeral_key: expected_server_ephemeral_key,
        }) = &self.binding
        else {
            unreachable!("only TLS 1.2 is implemented")
        };

        if server_ephemeral_key != expected_server_ephemeral_key {
            return Err(HandshakeVerificationError::InvalidServerEphemeralKey);
        }

        let (end_entity, intermediates) = self
            .certs
            .split_first()
            .ok_or(HandshakeVerificationError::MissingCerts)?;

        // Verify the end entity cert is valid for the provided server name
        // and that it chains to at least one of the roots we trust.
        verifier
            .verify_server_cert(end_entity, intermediates, server_name, time)
            .map_err(HandshakeVerificationError::ServerCert)?;

        // Verify the signature matches the certificate and key exchange parameters.
        let mut message = Vec::new();
        message.extend_from_slice(client_random);
        message.extend_from_slice(server_random);
        message.extend_from_slice(&server_ephemeral_key.kx_params());

        use webpki::ring as alg;
        let sig_alg = match self.sig.alg {
            SignatureAlgorithm::ECDSA_NISTP256_SHA256 => alg::ECDSA_P256_SHA256,
            SignatureAlgorithm::ECDSA_NISTP256_SHA384 => alg::ECDSA_P256_SHA384,
            SignatureAlgorithm::ECDSA_NISTP384_SHA256 => alg::ECDSA_P384_SHA256,
            SignatureAlgorithm::ECDSA_NISTP384_SHA384 => alg::ECDSA_P384_SHA384,
            SignatureAlgorithm::ED25519 => alg::ED25519,
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256 => alg::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384 => alg::RSA_PKCS1_2048_8192_SHA384,
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512 => alg::RSA_PKCS1_2048_8192_SHA512,
            SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY => {
                alg::RSA_PSS_2048_8192_SHA256_LEGACY_KEY
            }
            SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY => {
                alg::RSA_PSS_2048_8192_SHA384_LEGACY_KEY
            }
            SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY => {
                alg::RSA_PSS_2048_8192_SHA512_LEGACY_KEY
            }
        };

        let end_entity = webpki_types::CertificateDer::from(end_entity.0.as_slice());
        let end_entity = webpki::EndEntityCert::try_from(&end_entity)
            .map_err(|_| HandshakeVerificationError::InvalidEndEntityCertificate)?;

        end_entity
            .verify_signature(sig_alg, &message, &self.sig.sig)
            .map_err(|_| HandshakeVerificationError::InvalidServerSignature)?;

        Ok(())
    }
}

/// Errors that can occur when verifying a certificate chain or signature.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum HandshakeVerificationError {
    #[error("invalid end entity certificate")]
    InvalidEndEntityCertificate,
    #[error("missing server certificates")]
    MissingCerts,
    #[error("invalid server signature")]
    InvalidServerSignature,
    #[error("invalid server ephemeral key")]
    InvalidServerEphemeralKey,
    #[error("server certificate verification failed: {0}")]
    ServerCert(ServerCertVerifierError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixtures::ConnectionFixture, transcript::Transcript, webpki::RootCertStore};

    use hex::FromHex;
    use rstest::*;
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

    #[fixture]
    #[once]
    fn verifier() -> ServerCertVerifier {
        let mut root_store = RootCertStore {
            roots: webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|c| CertificateDer(c.to_vec()))
                .collect(),
        };

        // Add a cert which is no longer included in the Mozilla root store.
        root_store.roots.push(
            appliedzkp()
                .server_cert_data
                .certs
                .last()
                .expect("chain is valid")
                .clone(),
        );

        ServerCertVerifier::new(&root_store).unwrap()
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
        verifier: &ServerCertVerifier,
        #[case] mut data: ConnectionFixture,
    ) {
        // Remove the CA cert
        data.server_cert_data.certs.pop();

        assert!(data
            .server_cert_data
            .verify(
                verifier,
                data.connection_info.time,
                data.server_ephemeral_key(),
                &data.server_name,
            )
            .is_ok());
    }

    /// Expect chain verification to succeed even when a trusted CA is provided
    /// among the intermediate certs. webpki handles such cases properly.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_success_ca_explicit(
        verifier: &ServerCertVerifier,
        #[case] data: ConnectionFixture,
    ) {
        assert!(data
            .server_cert_data
            .verify(
                verifier,
                data.connection_info.time,
                data.server_ephemeral_key(),
                &data.server_name,
            )
            .is_ok());
    }

    /// Expect to fail since the end entity cert was not valid at the time.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_bad_time(
        verifier: &ServerCertVerifier,
        #[case] data: ConnectionFixture,
    ) {
        // unix time when the cert chain was NOT valid
        let bad_time: u64 = 1571465711;

        let err = data.server_cert_data.verify(
            verifier,
            bad_time,
            data.server_ephemeral_key(),
            &data.server_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            HandshakeVerificationError::ServerCert(_)
        ));
    }

    /// Expect to fail when no intermediate cert provided.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_no_interm_cert(
        verifier: &ServerCertVerifier,
        #[case] mut data: ConnectionFixture,
    ) {
        // Remove the CA cert
        data.server_cert_data.certs.pop();
        // Remove the intermediate cert
        data.server_cert_data.certs.pop();

        let err = data.server_cert_data.verify(
            verifier,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &data.server_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            HandshakeVerificationError::ServerCert(_)
        ));
    }

    /// Expect to fail when no intermediate cert provided even if a trusted CA
    /// cert is provided.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_no_interm_cert_with_ca_cert(
        verifier: &ServerCertVerifier,
        #[case] mut data: ConnectionFixture,
    ) {
        // Remove the intermediate cert
        data.server_cert_data.certs.remove(1);

        let err = data.server_cert_data.verify(
            verifier,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &data.server_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            HandshakeVerificationError::ServerCert(_)
        ));
    }

    /// Expect to fail because end-entity cert is wrong.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_bad_ee_cert(
        verifier: &ServerCertVerifier,
        #[case] mut data: ConnectionFixture,
    ) {
        let ee: &[u8] = include_bytes!("./fixtures/data/unknown/ee.der");

        // Change the end entity cert
        data.server_cert_data.certs[0] = CertificateDer(ee.to_vec());

        let err = data.server_cert_data.verify(
            verifier,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &data.server_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            HandshakeVerificationError::ServerCert(_)
        ));
    }

    /// Expect sig verification to fail because client_random is wrong.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_sig_ke_params_fail_bad_client_random(
        verifier: &ServerCertVerifier,
        #[case] mut data: ConnectionFixture,
    ) {
        let CertBinding::V1_2(CertBindingV1_2 { client_random, .. }) =
            &mut data.server_cert_data.binding;
        client_random[31] = client_random[31].wrapping_add(1);

        let err = data.server_cert_data.verify(
            verifier,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &data.server_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            HandshakeVerificationError::InvalidServerSignature
        ));
    }

    /// Expect sig verification to fail because the sig is wrong.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_sig_ke_params_fail_bad_sig(
        verifier: &ServerCertVerifier,
        #[case] mut data: ConnectionFixture,
    ) {
        data.server_cert_data.sig.sig[31] = data.server_cert_data.sig.sig[31].wrapping_add(1);

        let err = data.server_cert_data.verify(
            verifier,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &data.server_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            HandshakeVerificationError::InvalidServerSignature
        ));
    }

    /// Expect to fail because the dns name is not in the cert.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_check_dns_name_present_in_cert_fail_bad_host(
        verifier: &ServerCertVerifier,
        #[case] data: ConnectionFixture,
    ) {
        let bad_name = ServerName::Dns(DnsName::try_from("badhost.com").unwrap());

        let err = data.server_cert_data.verify(
            verifier,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &bad_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            HandshakeVerificationError::ServerCert(_)
        ));
    }

    /// Expect to fail because the ephemeral key provided is wrong.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_invalid_ephemeral_key(verifier: &ServerCertVerifier, #[case] data: ConnectionFixture) {
        let wrong_ephemeral_key = ServerEphemKey {
            typ: KeyType::SECP256R1,
            key: Vec::<u8>::from_hex(include_bytes!("./fixtures/data/unknown/pubkey")).unwrap(),
        };

        let err = data.server_cert_data.verify(
            verifier,
            data.connection_info.time,
            &wrong_ephemeral_key,
            &data.server_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            HandshakeVerificationError::InvalidServerEphemeralKey
        ));
    }

    /// Expect to fail when no cert provided.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_no_cert(
        verifier: &ServerCertVerifier,
        #[case] mut data: ConnectionFixture,
    ) {
        // Empty certs
        data.server_cert_data.certs = Vec::new();

        let err = data.server_cert_data.verify(
            verifier,
            data.connection_info.time,
            data.server_ephemeral_key(),
            &data.server_name,
        );

        assert!(matches!(
            err.unwrap_err(),
            HandshakeVerificationError::MissingCerts
        ));
    }
}
