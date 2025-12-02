use std::sync::{Mutex, Weak};

use crate::prover::{Prover, ProverError, state};

/// A controller for the prover.
#[derive(Clone)]
pub struct ProverControl {
    pub(crate) prover: Weak<Mutex<Prover<state::Connected>>>,
}

impl ProverControl {
    /// Returns whether the prover is decrypting the server traffic.
    pub fn is_decrypting(&self) -> bool {
        let Some(prover) = self.prover.upgrade() else {
            return false;
        };
        let prover = prover
            .lock()
            .expect("should be able to acquire lock for prover");
        prover.is_decrypting()
    }

    /// Enables or disables the decryption of server traffic.
    ///
    /// # Arguments
    ///
    /// * `enable` - If decryption should be enabled or disabled.
    pub fn enable_decryption(&self, enable: bool) -> Result<(), ProverError> {
        let Some(prover) = self.prover.upgrade() else {
            return Err(ProverError::state("prover not available anymore"));
        };
        let mut prover = prover
            .lock()
            .expect("should be able to acquire lock for prover");
        prover.enable_decryption(enable)
    }
}
