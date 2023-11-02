use std::error::Error;
use tls_mpc::MpcTlsError;

/// An error that can occur during TLS verification.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VerifierError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error("error occurred in MPC protocol: {0}")]
    MpcError(Box<dyn Error + Send + 'static>),
    #[error("{0}")]
    Other(Box<dyn Error + Send + 'static>),
}

impl From<MpcTlsError> for VerifierError {
    fn from(e: MpcTlsError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::OTError> for VerifierError {
    fn from(e: mpz_ot::OTError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::actor::kos::SenderActorError> for VerifierError {
    fn from(e: mpz_ot::actor::kos::SenderActorError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::actor::kos::ReceiverActorError> for VerifierError {
    fn from(e: mpz_ot::actor::kos::ReceiverActorError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::DecodeError> for VerifierError {
    fn from(e: mpz_garble::DecodeError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<tlsn_core::proof::SessionProofError> for VerifierError {
    fn from(e: tlsn_core::proof::SessionProofError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<tlsn_core::proof::substring::TranscriptProofError> for VerifierError {
    fn from(e: tlsn_core::proof::substring::TranscriptProofError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::VmError> for VerifierError {
    fn from(e: mpz_garble::VmError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<&str> for VerifierError {
    fn from(e: &str) -> Self {
        let err = Box::<dyn Error + Send + Sync + 'static>::from(e);
        Self::Other(err)
    }
}
