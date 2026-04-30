use std::sync::Arc;

use crate::prover::client::DecryptState;

/// A controller for the prover.
///
/// Can be used to control the decryption of server traffic.
#[derive(Clone, Debug)]
pub struct ProverControl {
    pub(crate) decrypt: Arc<DecryptState>,
}

impl ProverControl {
    /// Returns whether the prover is decrypting the server traffic.
    pub fn is_decrypting(&self) -> bool {
        self.decrypt.is_decrypting()
    }

    /// Enables or disables the decryption of server traffic.
    ///
    /// # Arguments
    ///
    /// * `enable` - If decryption should be enabled or disabled.
    pub fn enable_decryption(&self, enable: bool) {
        self.decrypt.enable_decryption(enable)
    }
}
