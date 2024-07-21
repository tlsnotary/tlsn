use web_time::SystemTime;

use crate::{
    cert::ServerCertDetails, dns::ServerName, ke::ServerKxDetails, msgs::handshake::Random,
    verify::ServerCertVerifier, Error,
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HandshakeData {
    /// Server certificate chain and related details.
    server_cert_details: ServerCertDetails,
    /// Key exchange details.
    server_kx_details: ServerKxDetails,
    /// Client random
    client_random: Random,
    /// Server random
    server_random: Random,
}

impl HandshakeData {
    /// Creates a new `HandshakeData` instance.
    pub fn new(
        server_cert_details: ServerCertDetails,
        server_kx_details: ServerKxDetails,
        client_random: Random,
        server_random: Random,
    ) -> Self {
        Self {
            server_cert_details,
            server_kx_details,
            client_random,
            server_random,
        }
    }

    /// Returns the server certificate chain.
    pub fn server_cert_details(&self) -> &ServerCertDetails {
        &self.server_cert_details
    }

    /// Returns the key exchange details.
    pub fn server_kx_details(&self) -> &ServerKxDetails {
        &self.server_kx_details
    }

    /// Returns the client random value.
    pub fn client_random(&self) -> &Random {
        &self.client_random
    }

    /// Returns the server random value.
    pub fn server_random(&self) -> &Random {
        &self.server_random
    }

    /// Verifies the handshake data.
    pub fn verify(
        &self,
        verifier: &impl ServerCertVerifier,
        time: SystemTime,
        server_name: &ServerName,
    ) -> Result<(), Error> {
        let (end_entity, intermediates) = self
            .server_cert_details
            .cert_chain()
            .split_first()
            .ok_or(Error::NoCertificatesPresented)?;

        // Verify the end entity cert is valid for the provided server name
        // and that it chains to at least one of the roots we trust.
        _ = verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            &mut self
                .server_cert_details
                .scts()
                .map(|sct| sct.as_slice())
                .unwrap_or(&[])
                .iter()
                .map(|sct| sct.0.as_slice()),
            self.server_cert_details.ocsp_response(),
            time,
        )?;

        // Verify the signature matches the certificate and key exchange parameters.
        let mut message = Vec::new();
        message.extend_from_slice(&self.client_random.0);
        message.extend_from_slice(&self.server_random.0);
        message.extend_from_slice(self.server_kx_details().kx_params());

        let sig = self.server_kx_details().kx_sig();
        _ = verifier.verify_tls12_signature(
            &message,
            &self.server_cert_details().cert_chain()[0],
            sig,
        )?;

        Ok(())
    }
}
