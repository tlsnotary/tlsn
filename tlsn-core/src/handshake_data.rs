use crate::{error::Error, utils::blake3, webpki_utils, HashCommitment, SessionHeader};
use serde::Serialize;

/// an x509 certificate in DER format
pub type CertDER = Vec<u8>;

/// Misc TLS handshake data which the User committed to before the User and the Notary engaged in 2PC
/// to compute the TLS session keys
///
/// The User should not reveal `tls_cert_chain` because the Notary would learn the webserver name
/// from it. The User also should not reveal `sig_ke_params` to the Notary, because
/// for ECDSA sigs it is possible to derive the pubkey from the sig and then use that pubkey to find out
/// the identity of the webserver.
//
/// Note that there is no need to commit to the ephemeral key because it will be signed explicitly
/// by the Notary
#[derive(Serialize, Clone, Default)]
pub struct HandshakeData {
    tls_cert_chain: Vec<CertDER>,
    sig_ke_params: ServerSignature,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
}

impl HandshakeData {
    pub fn new(
        tls_cert_chain: Vec<CertDER>,
        sig_ke_params: ServerSignature,
        client_random: Vec<u8>,
        server_random: Vec<u8>,
    ) -> Self {
        Self {
            tls_cert_chain,
            sig_ke_params,
            client_random,
            server_random,
        }
    }

    /// Creates a hash commitment to `self`
    pub fn commit(&self) -> Result<HashCommitment, Error> {
        let msg = self.serialize()?;
        Ok(blake3(&msg))
    }

    /// Verifies the TLS document against the DNS name `dns_name`:
    /// - end entity certificate was issued to `dns_name` and was valid at the time of the
    ///   notarization
    /// - certificate chain was signed by a trusted certificate authority
    /// - key exchange parameters were signed by the end entity certificate
    /// - commitment to misc TLS data is correct
    ///
    pub fn verify(self, header: &SessionHeader, dns_name: &str) -> Result<(), Error> {
        // Verify TLS certificate chain against local root certs. Some certs in the chain may
        // have expired at the time of this verification. We verify their validity at the time
        // of notarization.
        webpki_utils::verify_cert_chain(&self.tls_cert_chain, header.handshake_summary().time())?;

        let ee_cert = webpki_utils::extract_end_entity_cert(&self.tls_cert_chain)?;

        // check that TLS key exchange parameters were signed by the end-entity cert
        webpki_utils::verify_sig_ke_params(
            &ee_cert,
            &self.sig_ke_params,
            header.handshake_summary().ephemeral_ec_pubkey(),
            &self.client_random,
            &self.server_random,
        )?;

        webpki_utils::check_dns_name_present_in_cert(&ee_cert, dns_name)?;

        // Create a commitment and compare it to the value committed to earlier
        let expected = HandshakeData::new(
            self.tls_cert_chain,
            self.sig_ke_params,
            self.client_random,
            self.server_random,
        )
        .commit()?;
        if &expected != header.handshake_summary().handshake_commitment() {
            return Err(Error::CommitmentVerificationFailed);
        }

        Ok(())
    }

    fn serialize(&self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self).map_err(|_| Error::SerializationError)
    }
}

/// Algorithms that can be used for signing the TLS key exchange parameters
#[derive(Clone, Serialize, Default)]
#[allow(non_camel_case_types)]
pub enum KEParamsSigAlg {
    #[default]
    RSA_PKCS1_2048_8192_SHA256,
    ECDSA_P256_SHA256,
}

/// A server's signature over the TLS key exchange parameters
#[derive(Serialize, Clone, Default)]
pub struct ServerSignature {
    alg: KEParamsSigAlg,
    sig: Vec<u8>,
}

impl ServerSignature {
    pub fn new(alg: KEParamsSigAlg, sig: Vec<u8>) -> Self {
        Self { alg, sig }
    }

    pub fn alg(&self) -> &KEParamsSigAlg {
        &self.alg
    }

    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
}
