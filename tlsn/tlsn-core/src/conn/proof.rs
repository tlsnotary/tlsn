use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    dns::ServerName,
    msgs::handshake::DigitallySignedStruct,
    verify::{ServerCertVerifier, WebPkiVerifier},
};
use web_time::{Duration, UNIX_EPOCH};

use crate::conn::{
    Certificate, ConnectionInfo, HandshakeData, HandshakeDataV1_2, ServerIdentity, ServerSignature,
};

/// TLS server identity proof.
pub struct ServerIdentityProof {
    pub(crate) cert_chain: Vec<Certificate>,
    pub(crate) sig: ServerSignature,
    pub(crate) nonce: [u8; 16],
    pub(crate) identity: ServerIdentity,
}

/// Server identity proof verification error.
#[derive(Debug, thiserror::Error)]
pub enum ServerIdentityProofError {
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
    InvalidSignature,
}

impl ServerIdentityProof {
    /// Verifies the server identity proof with the default certificate root store
    /// provided by the `webpki-roots` crate.
    ///
    /// # Arguments
    ///
    /// * `info` - The connection information.
    /// * `handshake` - The handshake data.
    pub fn verify(
        self,
        info: &ConnectionInfo,
        handshake: &HandshakeData,
    ) -> Result<ServerIdentity, ServerIdentityProofError> {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref(),
                ta.subject_public_key_info.as_ref(),
                ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
            )
        }));
        self.verify_with_root_store(info, handshake, root_store)
    }

    /// Verifies the server identity proof with the provided certificate root store.
    ///
    /// # Arguments
    ///
    /// * `info` - The connection information.
    /// * `handshake` - The handshake data.
    /// * `root_store` - The root certificate store.
    pub fn verify_with_root_store(
        self,
        info: &ConnectionInfo,
        handshake: &HandshakeData,
        root_store: RootCertStore,
    ) -> Result<ServerIdentity, ServerIdentityProofError> {
        let cert_verifier = WebPkiVerifier::new(root_store, None);

        #[allow(irrefutable_let_patterns)]
        let ServerIdentity::Dns(server_name) = &self.identity
        else {
            unreachable!("only DNS identities are implemented")
        };

        #[allow(irrefutable_let_patterns)]
        let HandshakeData::V1_2(HandshakeDataV1_2 {
            client_random,
            server_random,
            server_ephemeral_key,
        }) = handshake
        else {
            unreachable!("only TLS 1.2 is implemented")
        };

        // Verify server name
        let server_name = ServerName::try_from(server_name.as_ref())
            .map_err(|_| ServerIdentityProofError::InvalidIdentity(self.identity.clone()))?;

        let cert_chain = self
            .cert_chain
            .into_iter()
            .map(|cert| tls_core::key::Certificate(cert.0))
            .collect::<Vec<_>>();

        // Verify server certificate
        let (end_entity, intermediates) = cert_chain
            .split_first()
            .ok_or(ServerIdentityProofError::MissingCerts)?;

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
            .map_err(|_| ServerIdentityProofError::InvalidCert)?;

        // Verify the signature matches the certificate and key exchange parameters.
        let mut message = Vec::new();
        message.extend_from_slice(client_random);
        message.extend_from_slice(server_random);
        message.extend_from_slice(&server_ephemeral_key.key);

        let dss = DigitallySignedStruct::new(self.sig.scheme.to_tls_core(), self.sig.sig.clone());

        _ = cert_verifier
            .verify_tls12_signature(&message, end_entity, &dss)
            .map_err(|_| ServerIdentityProofError::InvalidSignature)?;

        Ok(self.identity)
    }
}
