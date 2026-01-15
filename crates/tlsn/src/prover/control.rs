use crate::prover::client::ClientHandle;

/// A controller for the prover.
///
/// Can be used to control the decryption of server traffic.
#[derive(Clone, Debug)]
pub struct ProverControl {
    pub(crate) handle: ClientHandle,
}

impl ProverControl {
    /// Returns whether the prover is decrypting the server traffic.
    pub fn is_decrypting(&self) -> bool {
        self.handle.is_decrypting()
    }

    /// Enables or disables the decryption of server traffic.
    ///
    /// # Arguments
    ///
    /// * `enable` - If decryption should be enabled or disabled.
    pub fn enable_decryption(&self, enable: bool) -> Result<(), ControlError> {
        self.handle.enable_decryption(enable)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Unable to send control command to prover.")]
pub struct ControlError;
