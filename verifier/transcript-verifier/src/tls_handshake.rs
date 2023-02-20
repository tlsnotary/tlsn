use crate::{error::Error, utils::blake3, webpki_utils};
use serde::Serialize;
use transcript_core::{signed::SignedHandshake, tls_handshake::HandshakeData, HashCommitment};

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
            self.handshake_data.tls_cert_chain(),
            self.signed_handshake.time(),
        )?;

        let ee_cert = webpki_utils::extract_end_entity_cert(self.handshake_data.tls_cert_chain())?;

        self.verify_tls_commitment(
            &self.handshake_data,
            self.signed_handshake.handshake_commitment(),
        )?;

        //check that TLS key exchange parameters were signed by the end-entity cert
        webpki_utils::verify_sig_ke_params(
            &ee_cert,
            self.handshake_data.sig_ke_params(),
            self.signed_handshake.ephemeral_ec_pubkey(),
            self.handshake_data.client_random(),
            self.handshake_data.server_random(),
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
        let msg = handshake_data.serialize().map_err(Error::from)?;
        if blake3(&msg) != *commitment {
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

impl std::convert::From<transcript_core::tls_handshake::TLSHandshake> for TLSHandshake {
    fn from(h: transcript_core::tls_handshake::TLSHandshake) -> Self {
        TLSHandshake {
            handshake_data: h.handshake_data().clone(),
            signed_handshake: h.signed_handshake().clone(),
        }
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
