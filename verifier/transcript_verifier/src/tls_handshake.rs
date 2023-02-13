use super::{signed::SignedHandshake, utils::blake3, webpki_utils, Error, HashCommitment};
use serde::Serialize;

/// TLSHandshake contains all the info needed to verify the authenticity of the TLS handshake
#[derive(Serialize, Default, Clone)]
pub struct TLSHandshake {
    signed_handshake: SignedHandshake,
    handshake_data: HandshakeData,
}

impl TLSHandshake {
    pub fn new(signed_handshake: SignedHandshake, handshake_data: HandshakeData) -> Self {
        Self {
            signed_handshake,
            handshake_data,
        }
    }

    /// Verifies the TLS document against the DNS name `dns_name`:
    /// - end entity certificate was issued to `dns_name` and was valid at the time of the
    ///   notarization
    /// - certificate chain was signed by a trusted certificate authority
    /// - key exchange parameters were signed by the end entity certificate
    /// - commitment to misc TLS data is correct
    ///
    pub fn verify(&self, dns_name: &str) -> Result<(), Error> {
        // Verify TLS certificate chain against local root certs. Some certs in the chain may
        // have expired at the time of this verification. We verify their validity at the time
        // of notarization.
        webpki_utils::verify_cert_chain(
            &self.handshake_data.tls_cert_chain,
            self.signed_handshake.time(),
        )?;

        let ee_cert = webpki_utils::extract_end_entity_cert(&self.handshake_data.tls_cert_chain)?;

        self.verify_tls_commitment(
            &self.handshake_data,
            self.signed_handshake.handshake_commitment(),
        )?;

        //check that TLS key exchange parameters were signed by the end-entity cert
        webpki_utils::verify_sig_ke_params(
            &ee_cert,
            &self.handshake_data.sig_ke_params,
            self.signed_handshake.ephemeral_ec_pubkey(),
            &self.handshake_data.client_random,
            &self.handshake_data.server_random,
        )?;

        webpki_utils::check_dns_name_present_in_cert(&ee_cert, dns_name)?;

        Ok(())
    }

    /// Verifies the commitment to misc TLS handshake data
    fn verify_tls_commitment(
        &self,
        handshake_data: &HandshakeData,
        commitment: &HashCommitment,
    ) -> Result<(), Error> {
        if blake3(&handshake_data.serialize()?) != *commitment {
            return Err(Error::CommittedTLSCheckFailed);
        }
        Ok(())
    }

    pub fn signed_handshake(&self) -> &SignedHandshake {
        &self.signed_handshake
    }

    pub fn handshake_data(&self) -> &HandshakeData {
        &self.handshake_data
    }
}

/// an x509 certificate in DER format
pub type CertDER = Vec<u8>;

/// Misc TLS handshake data which the User committed to before the User and the Notary engaged in 2PC
/// to compute the TLS session keys
///
/// The User should not reveal `tls_cert_chain` because the Notary would learn the webserver name
/// from it. The User also should not reveal `signature_over_ephemeral_key` to the Notary, because
/// for ECDSA sigs it is possible to derive the pubkey from the sig and then use that pubkey to find out
/// the identity of the webserver.
//
/// Note that there is no need to commit to the ephemeral key because it will be signed explicitely
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

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self).map_err(|_| Error::SerializationError)
    }

    pub fn tls_cert_chain(&self) -> &Vec<CertDER> {
        &self.tls_cert_chain
    }
}

/// Types of the ephemeral EC pubkey currently supported by TLSNotary
#[derive(Clone, Serialize, Default)]
pub enum EphemeralECPubkeyType {
    #[default]
    P256,
}

/// The ephemeral EC public key (part of the TLS key exchange parameters)
#[derive(Clone, Serialize, Default)]
pub struct EphemeralECPubkey {
    typ: EphemeralECPubkeyType,
    pubkey: Vec<u8>,
}

impl EphemeralECPubkey {
    pub fn new(typ: EphemeralECPubkeyType, pubkey: Vec<u8>) -> Self {
        Self { typ, pubkey }
    }

    pub fn typ(&self) -> &EphemeralECPubkeyType {
        &self.typ
    }

    pub fn pubkey(&self) -> &Vec<u8> {
        &self.pubkey
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

    pub fn sig(&self) -> &Vec<u8> {
        &self.sig
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::doc::validated::test::validated_doc;
    use rstest::{fixture, rstest};

    #[fixture]
    // Returns a correct TLSHandshake struct
    fn tls_handshake() -> TLSHandshake {
        let doc = validated_doc();
        doc.tls_handshake().clone()
    }

    #[rstest]
    // Expect verify() to succeed
    fn verify_success(tls_handshake: TLSHandshake) {
        assert!(tls_handshake.verify("tlsnotary.org").is_ok())
    }

    #[rstest]
    // Expect verify() to fail since DNS name is wrong
    fn verify_fail_wrong_dns_name(tls_handshake: TLSHandshake) {
        assert!(tls_handshake.verify("tlsnotary2.org").is_err())
    }

    #[rstest]
    // Expect verify_tls_commitment() to fail since the commitment is wrong
    fn verify_fail_wrong_commitment(mut tls_handshake: TLSHandshake) {
        let mut commitment = *tls_handshake.signed_handshake.handshake_commitment();
        // corrupt a byte of the commitment
        commitment[0] = commitment[0].checked_add(1).unwrap_or(0);
        tls_handshake
            .signed_handshake
            .set_handshake_commitment(commitment);

        assert!(tls_handshake.verify("tlsnotary.org").is_err())
    }
}
