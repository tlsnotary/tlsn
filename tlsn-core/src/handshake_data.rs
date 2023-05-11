use crate::{
    end_entity_cert::EndEntityCert, error::Error, utils::blake3, HandshakeSummary, KEParams,
};
use mpc_core::hash::Hash;
use serde::{Deserialize, Serialize};

/// Misc TLS handshake data which the User committed to before the User and the Notary engaged in 2PC
/// to compute the TLS session keys
///
/// The User should not reveal `tls_cert_chain` because the Notary would learn the webserver name
/// from it. The User also should not reveal `server_signature` to the Notary, because
/// for ECDSA sigs it is possible to derive the pubkey from the sig and then use that pubkey to find out
/// the identity of the webserver.
#[derive(Serialize, Clone, Deserialize)]
pub struct HandshakeData {
    /// End-entity certificate
    end_entity_cert: EndEntityCert,
    /// Intermediate certificates in descending order (root certificate is allowed to be present)
    interm_certs: Vec<Vec<u8>>,
    /// Key exchange parameters
    ke_params: KEParams,
    /// Signature made by the `end_entity_cert` over the `ke_params`
    server_signature: ServerSignature,
}

impl HandshakeData {
    pub fn new(
        end_entity_cert: EndEntityCert,
        interm_certs: Vec<Vec<u8>>,
        ke_params: KEParams,
        server_signature: ServerSignature,
    ) -> Self {
        Self {
            end_entity_cert,
            interm_certs,
            ke_params,
            server_signature,
        }
    }

    /// Creates a hash commitment to `self`
    pub fn commit(&self) -> Result<Hash, Error> {
        let msg = self.serialize()?;
        Ok(Hash::from(blake3(&msg)))
    }

    /// Verifies this `HandshakeData` against a [HandshakeSummary] and the `dns_name`, making
    /// sure that:
    /// - end-entity certificate was issued to `dns_name` and was valid at the time of the
    ///   notarization
    /// - certificate chain was signed by a trusted certificate authority
    /// - key exchange parameters were signed by the end-entity certificate
    /// - User's commitment to this `HandshakeData` is correct
    ///
    pub fn verify(self, hs_summary: &HandshakeSummary, dns_name: &str) -> Result<(), Error> {
        // Ephemeral pubkey must match the one which the Notary signed
        if hs_summary.ephemeral_ec_pubkey() != self.ke_params.ephem_pubkey() {
            return Err(Error::ValidationError);
        }

        // Verify TLS certificate chain against local root certs. Some certs in the chain may
        // have expired at the time of this verification. We verify their validity against the time
        // of notarization.
        self.end_entity_cert
            .verify_is_valid_tls_server_cert(&self.interm_certs, hs_summary.time())?;

        // check that TLS key exchange parameters were signed by the end-entity cert
        self.end_entity_cert
            .verify_signature(&self.ke_params.to_bytes()?, &self.server_signature)?;

        // check that DNS name is valid
        self.end_entity_cert
            .verify_is_valid_for_dns_name(dns_name)?;

        // Create a commitment and compare it to the value committed to earlier
        let expected = HandshakeData::new(
            self.end_entity_cert,
            self.interm_certs,
            self.ke_params,
            self.server_signature,
        )
        .commit()?;
        if &expected != hs_summary.handshake_commitment() {
            return Err(Error::CommitmentVerificationFailed);
        }

        Ok(())
    }

    fn serialize(&self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self).map_err(|_| Error::SerializationError)
    }
}

/// Algorithm used by the server to sign the TLS key exchange parameters
#[derive(Clone, Serialize, Deserialize, Default, Debug)]
#[allow(non_camel_case_types)]
pub enum ServerSigAlg {
    #[default]
    RSA_PKCS1_2048_8192_SHA256,
    ECDSA_P256_SHA256,
}

/// A server's signature over the TLS key exchange parameters
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ServerSignature {
    alg: ServerSigAlg,
    sig: Vec<u8>,
}

impl ServerSignature {
    pub fn new(alg: ServerSigAlg, sig: Vec<u8>) -> Self {
        Self { alg, sig }
    }

    pub fn alg(&self) -> &ServerSigAlg {
        &self.alg
    }

    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
}
