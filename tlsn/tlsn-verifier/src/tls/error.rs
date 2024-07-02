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
    MpcError(Box<dyn Error + Send + Sync + 'static>),
    #[error("Range exceeds transcript length")]
    InvalidRange,
}

impl From<uid_mux::yamux::ConnectionError> for VerifierError {
    fn from(e: uid_mux::yamux::ConnectionError) -> Self {
        Self::IOError(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            e,
        ))
    }
}

impl From<mpz_common::ContextError> for VerifierError {
    fn from(e: mpz_common::ContextError) -> Self {
        Self::MpcError(Box::new(e))
    }
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

impl From<mpz_ot::kos::SenderError> for VerifierError {
    fn from(e: mpz_ot::kos::SenderError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::kos::ReceiverError> for VerifierError {
    fn from(e: mpz_ot::kos::ReceiverError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::protocol::deap::DEAPError> for VerifierError {
    fn from(e: mpz_garble::protocol::deap::DEAPError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::VerifyError> for VerifierError {
    fn from(e: mpz_garble::VerifyError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::MemoryError> for VerifierError {
    fn from(e: mpz_garble::MemoryError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<tlsn_core::proof::SessionProofError> for VerifierError {
    fn from(e: tlsn_core::proof::SessionProofError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::VmError> for VerifierError {
    fn from(e: mpz_garble::VmError) -> Self {
        Self::MpcError(Box::new(e))
    }
}
