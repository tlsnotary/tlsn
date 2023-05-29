use crate::{
    key::Certificate,
    msgs::handshake::{CertificatePayload, SCTList},
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerCertDetails {
    cert_chain: CertificatePayload,
    ocsp_response: Vec<u8>,
    scts: Option<SCTList>,
}

impl ServerCertDetails {
    pub fn new(
        cert_chain: CertificatePayload,
        ocsp_response: Vec<u8>,
        scts: Option<SCTList>,
    ) -> Self {
        Self {
            cert_chain,
            ocsp_response,
            scts,
        }
    }

    pub fn cert_chain(&self) -> &[Certificate] {
        &self.cert_chain
    }

    pub fn ocsp_response(&self) -> &[u8] {
        &self.ocsp_response
    }

    pub fn scts(&self) -> Option<&SCTList> {
        self.scts.as_ref()
    }
}
