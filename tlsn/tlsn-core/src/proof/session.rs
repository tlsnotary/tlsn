use web_time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use mpz_core::{commit::Decommitment, serialize::CanonicalSerialize};
use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    dns::ServerName as TlsServerName,
    handshake::HandshakeData,
    verify::{ServerCertVerifier, WebPkiVerifier},
};

use crate::{
    session::SessionHeader,
    signature::{Signature, SignatureVerifyError},
    HandshakeSummary, NotaryPublicKey, ServerName,
};

/// An error that can occur while verifying a [`SessionProof`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionProofError {
    /// Session proof is missing Notary signature
    #[error("session proof is missing notary signature")]
    MissingNotarySignature,
    /// Invalid signature
    #[error(transparent)]
    InvalidSignature(#[from] SignatureVerifyError),
    /// Invalid server name.
    #[error("invalid server name: {0}")]
    InvalidServerName(String),
    /// Invalid handshake
    #[error("handshake verification failed: {0}")]
    InvalidHandshake(String),
    /// Invalid server certificate
    #[error("server certificate verification failed: {0}")]
    InvalidServerCertificate(String),
}

/// A session proof which is created from a [crate::session::NotarizedSession]
///
/// Proof of the TLS handshake, server identity, and commitments to the transcript.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionProof {
    /// The session header
    pub header: SessionHeader,
    /// Signature for the session header, if the notary signed it
    pub signature: Option<Signature>,
    /// Information about the server
    pub session_info: SessionInfo,
}

impl SessionProof {
    /// Verify the session proof.
    ///
    /// # Arguments
    ///
    /// * `notary_public_key` - The public key of the notary.
    /// * `cert_verifier` - The certificate verifier.
    pub fn verify(
        &self,
        notary_public_key: impl Into<NotaryPublicKey>,
        cert_verifier: &impl ServerCertVerifier,
    ) -> Result<(), SessionProofError> {
        // Verify notary signature
        let signature = self
            .signature
            .as_ref()
            .ok_or(SessionProofError::MissingNotarySignature)?;

        signature.verify(&self.header.to_bytes(), notary_public_key)?;
        self.session_info
            .verify(self.header.handshake_summary(), cert_verifier)?;

        Ok(())
    }

    /// Verify the session proof using trust anchors from the `webpki-roots` crate.
    ///
    /// # Arguments
    ///
    /// * `notary_public_key` - The public key of the notary.
    pub fn verify_with_default_cert_verifier(
        &self,
        notary_public_key: impl Into<NotaryPublicKey>,
    ) -> Result<(), SessionProofError> {
        self.verify(notary_public_key, &default_cert_verifier())
    }
}

/// Contains information about the session
///
/// Includes the [ServerName] and the decommitment to the [HandshakeData].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    /// The server name.
    pub server_name: ServerName,
    /// Decommitment to the TLS handshake and server identity.
    pub handshake_decommitment: Decommitment<HandshakeData>,
}

impl SessionInfo {
    /// Verify the session info.
    pub fn verify(
        &self,
        handshake_summary: &HandshakeSummary,
        cert_verifier: &impl ServerCertVerifier,
    ) -> Result<(), SessionProofError> {
        // Verify server name
        let server_name = TlsServerName::try_from(self.server_name.as_ref())
            .map_err(|e| SessionProofError::InvalidServerName(e.to_string()))?;

        // Verify handshake
        self.handshake_decommitment
            .verify(handshake_summary.handshake_commitment())
            .map_err(|e| SessionProofError::InvalidHandshake(e.to_string()))?;

        // Verify server certificate
        self.handshake_decommitment
            .data()
            .verify(
                cert_verifier,
                UNIX_EPOCH + Duration::from_secs(handshake_summary.time()),
                &server_name,
            )
            .map_err(|e| SessionProofError::InvalidServerCertificate(e.to_string()))?;

        Ok(())
    }

    /// Verify the session info using trust anchors from the `webpki-roots` crate.
    ///
    /// # Arguments
    ///
    /// * `handshake_summary` - The summary of the handshake.
    pub fn verify_with_default_cert_verifier(
        &self,
        handshake_summary: &HandshakeSummary,
    ) -> Result<(), SessionProofError> {
        self.verify(handshake_summary, &default_cert_verifier())
    }
}

/// Create a new [`WebPkiVerifier`] with the default trust anchors from the `webpki-roots` crate.
pub fn default_cert_verifier() -> WebPkiVerifier {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    use crate::fixtures::cert::{appliedzkp, tlsnotary, TestData};
    use tls_core::{dns::ServerName, key::Certificate};
    use web_time::SystemTime;

    /// Expect chain verification to succeed
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_sucess_ca_implicit(#[case] data: TestData) {
        assert!(default_cert_verifier()
            .verify_server_cert(
                &data.ee,
                &[data.inter],
                &ServerName::try_from(data.dns_name.as_ref()).unwrap(),
                &mut std::iter::empty(),
                &[],
                SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
            )
            .is_ok());
    }

    /// Expect chain verification to succeed even when a trusted CA is provided among the intermediate
    /// certs. webpki handles such cases properly.
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_success_ca_explicit(#[case] data: TestData) {
        assert!(default_cert_verifier()
            .verify_server_cert(
                &data.ee,
                &[data.inter, data.ca],
                &ServerName::try_from(data.dns_name.as_ref()).unwrap(),
                &mut std::iter::empty(),
                &[],
                SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
            )
            .is_ok());
    }

    /// Expect to fail since the end entity cert was not valid at the time
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_bad_time(#[case] data: TestData) {
        // unix time when the cert chain was NOT valid
        let bad_time: u64 = 1571465711;

        let err = default_cert_verifier().verify_server_cert(
            &data.ee,
            &[data.inter],
            &ServerName::try_from(data.dns_name.as_ref()).unwrap(),
            &mut std::iter::empty(),
            &[],
            SystemTime::UNIX_EPOCH + Duration::from_secs(bad_time),
        );

        assert!(matches!(
            err.unwrap_err(),
            tls_core::Error::InvalidCertificateData(_)
        ));
    }

    /// Expect to fail when no intermediate cert provided
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_no_interm_cert(#[case] data: TestData) {
        let err = default_cert_verifier().verify_server_cert(
            &data.ee,
            &[],
            &ServerName::try_from(data.dns_name.as_ref()).unwrap(),
            &mut std::iter::empty(),
            &[],
            SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
        );

        assert!(matches!(
            err.unwrap_err(),
            tls_core::Error::InvalidCertificateData(_)
        ));
    }

    /// Expect to fail when no intermediate cert provided even if a trusted CA cert is provided
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_no_interm_cert_with_ca_cert(#[case] data: TestData) {
        let err = default_cert_verifier().verify_server_cert(
            &data.ee,
            &[data.ca],
            &ServerName::try_from(data.dns_name.as_ref()).unwrap(),
            &mut std::iter::empty(),
            &[],
            SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
        );

        assert!(matches!(
            err.unwrap_err(),
            tls_core::Error::InvalidCertificateData(_)
        ));
    }

    /// Expect to fail because end-entity cert is wrong
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_cert_chain_fail_bad_ee_cert(#[case] data: TestData) {
        let ee: &[u8] = include_bytes!("../fixtures/testdata/key_exchange/unknown/ee.der");

        let err = default_cert_verifier().verify_server_cert(
            &Certificate(ee.to_vec()),
            &[data.inter],
            &ServerName::try_from(data.dns_name.as_ref()).unwrap(),
            &mut std::iter::empty(),
            &[],
            SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
        );

        assert!(matches!(
            err.unwrap_err(),
            tls_core::Error::InvalidCertificateData(_)
        ));
    }

    /// Expect to succeed when key exchange params signed correctly with a cert
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_sig_ke_params_success(#[case] data: TestData) {
        assert!(default_cert_verifier()
            .verify_tls12_signature(&data.signature_msg(), &data.ee, &data.dss())
            .is_ok());
    }

    /// Expect sig verification to fail because client_random is wrong
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_sig_ke_params_fail_bad_client_random(#[case] mut data: TestData) {
        data.cr.0[31] = data.cr.0[31].wrapping_add(1);

        assert!(default_cert_verifier()
            .verify_tls12_signature(&data.signature_msg(), &data.ee, &data.dss())
            .is_err());
    }

    /// Expect sig verification to fail because the sig is wrong
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_verify_sig_ke_params_fail_bad_sig(#[case] mut data: TestData) {
        data.sig[31] = data.sig[31].wrapping_add(1);

        assert!(default_cert_verifier()
            .verify_tls12_signature(&data.signature_msg(), &data.ee, &data.dss())
            .is_err());
    }

    /// Expect to fail because the dns name is not in the cert
    #[rstest]
    #[case::tlsnotary(tlsnotary())]
    #[case::appliedzkp(appliedzkp())]
    fn test_check_dns_name_present_in_cert_fail_bad_host(#[case] data: TestData) {
        let bad_name = ServerName::try_from("badhost.com").unwrap();

        assert!(default_cert_verifier()
            .verify_server_cert(
                &data.ee,
                &[data.inter, data.ca],
                &bad_name,
                &mut std::iter::empty(),
                &[],
                SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
            )
            .is_err());
    }
}
