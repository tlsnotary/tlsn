use crate::error::Error;
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

    pub fn sig_ke_params(&self) -> &ServerSignature {
        &self.sig_ke_params
    }

    pub fn client_random(&self) -> &Vec<u8> {
        &self.client_random
    }

    pub fn server_random(&self) -> &Vec<u8> {
        &self.server_random
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
