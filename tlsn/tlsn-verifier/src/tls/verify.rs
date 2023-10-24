//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use super::{state::Verify, Verifier, VerifierError};

impl Verifier<Verify> {
    /// Verify the TLS session.
    pub async fn finalize(self) -> Result<(), VerifierError> {
        todo!()
    }
}
