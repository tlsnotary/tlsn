use crate::msgs::handshake::DigitallySignedStruct;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerKxDetails {
    kx_params: Vec<u8>,
    kx_sig: DigitallySignedStruct,
}

impl ServerKxDetails {
    /// Creates a new `ServerKxDetails` instance.
    pub fn new(params: Vec<u8>, sig: DigitallySignedStruct) -> Self {
        Self {
            kx_params: params,
            kx_sig: sig,
        }
    }

    /// Returns the key exchange parameters.
    pub fn kx_params(&self) -> &[u8] {
        &self.kx_params
    }

    /// Returns the key exchange signature.
    pub fn kx_sig(&self) -> &DigitallySignedStruct {
        &self.kx_sig
    }
}
