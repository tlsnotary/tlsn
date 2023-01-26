use super::{signed::SignedTLS, utils::blake3, webpki_utils, Error};
use serde::Serialize;

/// The document containing all the info needed to verify the authenticity of the TLS session.
#[derive(Serialize)]
pub struct TLSDoc {
    signed_tls: SignedTLS,
    committed_tls: CommittedTLS,
}

impl TLSDoc {
    pub fn new(signed_tls: SignedTLS, committed_tls: CommittedTLS) -> Self {
        Self {
            signed_tls,
            committed_tls,
        }
    }

    /// Verifies the TLS document against the DNS name `dns_name`:
    /// - end entity certificate was issued to `dns_name` and was valid at the time of the
    ///   notarization
    /// - certificate chain was signed by a trusted certificate authority
    /// - key exchange parameters were signed by the end entity certificate
    /// - commitment to misc TLS data is correct
    ///
    pub fn verify(&self, dns_name: String) -> Result<(), Error> {
        // Verify TLS certificate chain against local root certs. Some certs in the chain may
        // have expired at the time of this verification. We verify their validity at the time
        // of notarization.
        webpki_utils::verify_cert_chain(
            &self.committed_tls.tls_cert_chain,
            self.signed_tls.time(),
        )?;

        let ee_cert = webpki_utils::extract_end_entity_cert(&self.committed_tls.tls_cert_chain)?;

        self.verify_tls_commitment(&self.committed_tls, self.signed_tls.commitment_to_tls())?;

        //check that TLS key exchange parameters were signed by the end-entity cert
        webpki_utils::verify_sig_ke_params(
            &ee_cert,
            &self.committed_tls.sig_ke_params,
            self.signed_tls.ephemeral_ec_pubkey(),
            &self.committed_tls.client_random,
            &self.committed_tls.server_random,
        )?;

        webpki_utils::check_dns_name_present_in_cert(&ee_cert, dns_name)?;

        Ok(())
    }

    /// Verifies the commitment to misc TLS data
    fn verify_tls_commitment(
        &self,
        committed_tls: &CommittedTLS,
        commitment: &[u8; 32],
    ) -> Result<(), Error> {
        if blake3(&committed_tls.serialize()?) != *commitment {
            return Err(Error::CommittedTLSCheckFailed);
        }
        Ok(())
    }

    pub fn signed_tls(&self) -> &SignedTLS {
        &self.signed_tls
    }

    pub fn committed_tls(&self) -> &CommittedTLS {
        &self.committed_tls
    }
}

/// an x509 certificate in DER format
pub type CertDER = Vec<u8>;

/// Misc TLS data which the User committed to before the User and the Notary engaged in 2PC
/// to compute the TLS session keys
///
/// The User should not reveal `tls_cert_chain` because the Notary would learn the webserver name
/// from it. The User also should not reveal `signature_over_ephemeral_key` to the Notary, because
/// for ECDSA sigs it is possible to derive the pubkey from the sig and then use that pubkey to find out
/// the identity of the webserver.
//
/// Note that there is no need to commit to the ephemeral key because it will be signed explicitely
/// by the Notary
#[derive(Serialize, Clone)]
pub struct CommittedTLS {
    tls_cert_chain: Vec<CertDER>,
    sig_ke_params: SignatureKeyExchangeParams,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
}

impl CommittedTLS {
    pub fn new(
        tls_cert_chain: Vec<CertDER>,
        sig_ke_params: SignatureKeyExchangeParams,
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
}

/// Types of the ephemeral EC pubkey currently supported by TLSNotary
#[derive(Clone, Serialize)]
pub enum EphemeralECPubkeyType {
    P256,
}

/// The ephemeral EC public key (part of the TLS key exchange parameters)
#[derive(Clone, Serialize)]
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
#[derive(Clone, Serialize)]
pub enum SigKEParamsAlg {
    RSA_PKCS1_2048_8192_SHA256,
    ECDSA_P256_SHA256,
}

/// A signature over the TLS key exchange params
#[derive(Serialize, Clone)]
pub struct SignatureKeyExchangeParams {
    alg: SigKEParamsAlg,
    sig: Vec<u8>,
}

impl SignatureKeyExchangeParams {
    pub fn new(alg: SigKEParamsAlg, sig: Vec<u8>) -> Self {
        Self { alg, sig }
    }

    pub fn alg(&self) -> &SigKEParamsAlg {
        &self.alg
    }

    pub fn sig(&self) -> &Vec<u8> {
        &self.sig
    }
}
