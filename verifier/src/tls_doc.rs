use super::{signed::SignedTLS, webpki_utils, Error};

// The doc containing all the info needed to verify the authenticity of the TLS session.
#[derive(Clone)]
pub struct TLSDoc {
    version: u8,
    pub signed_tls: SignedTLS,
    committedTLS: CommittedTLS,
}

impl TLSDoc {
    // pub fn new() -> Self {
    //     //todo
    // }

    /// verifies the TLSDoc. Checks that `hostname` is present in the leaf certificate.
    pub fn verify(&self, hostname: String) -> Result<(), Error> {
        // check TLS certificate chain against local root certs. Some certs in the chain may
        // have expired at the time of this verification. We check their validity at the time
        // of notarization

        webpki_utils::verify_cert_chain(&self.committedTLS.tls_cert_chain, self.signed_tls.time)?;

        let leaf_cert = webpki_utils::extract_leaf_cert(&self.committedTLS.tls_cert_chain)?;

        self.check_tls_commitment(&self.committedTLS, &self.signed_tls.commitment_to_TLS)?;

        //check that TLS key exchange parameters were signed by the leaf cert
        webpki_utils::verify_sig_ke_params(
            &leaf_cert,
            &self.committedTLS.sig_ke_params,
            &self.signed_tls.ephemeralECPubkey,
            &self.committedTLS.client_random,
            &self.committedTLS.server_random,
        )?;

        webpki_utils::check_hostname_present_in_cert(&leaf_cert, hostname)?;

        Ok(())
    }

    // check the commitment to misc TLS data
    fn check_tls_commitment(
        &self,
        committedTLS: &CommittedTLS,
        commitment: &[u8; 32],
    ) -> Result<(), Error> {
        let serialize = committedTLS.serialize();
        // hash `serialize` and compare to `commitment`
        Ok(())
    }
}

// an x509 cert in DER format
pub type CertDER = Vec<u8>;

// Misc TLS data which the User committed to before the User and the Notary engaged in 2PC
// to compute the TLS session keys
//
// The User should not reveal `tls_cert_chain` because the Notary would learn the webserver name
// from it. The User also should not reveal `signature_over_ephemeral_key` to the Notary, because
// for ECDSA sigs it is possible to derive the pubkey from the sig and then use that pubkey to find out
// the identity of the webserver.
//
// Note that there is no need to commit to the ephemeral key because it will be signed explicitely
// by the Notary
#[derive(Clone)]
struct CommittedTLS {
    pub tls_cert_chain: Vec<CertDER>,
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

    // return a serialized structure which can be hashed
    pub fn serialize(&self) -> Vec<u8> {
        vec![0u8; 100]
    }
}

/// Types of the ephemeral EC pubkey supported by TLSNotary
#[derive(Clone)]
pub enum EphemeralECPubkeyType {
    p256,
    ed25519,
}

/// The ephemeral EC public key (part of the TLS key exchange parameters)
#[derive(Clone)]
pub struct EphemeralECPubkey {
    pub typ: EphemeralECPubkeyType,
    pub pubkey: Vec<u8>,
}

/// Algorithms that can be used for signing the TLS key exchange parameters
#[derive(Clone)]
pub enum SigKEParamsAlg {
    RSA_PKCS1_2048_8192_SHA256,
    ECDSA_P256_SHA256,
}

/// signature over the TLS key exchange params
#[derive(Clone)]
pub struct SignatureKeyExchangeParams {
    pub alg: SigKEParamsAlg,
    pub sig: Vec<u8>,
}
