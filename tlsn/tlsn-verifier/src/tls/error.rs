use std::error::Error;
use tls_mpc::MpcTlsError;
use tlsn_core::proof::{SessionProofError, SubstringProofError};

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
    #[error(transparent)]
    VMError(#[from] mpz_garble::VmError),
    #[error("Transcript value cannot be decoded from VM thread")]
    TranscriptDecodeError,
    #[error(transparent)]
    DecodeError(#[from] mpz_garble::DecodeError),
    #[error("Invalid handshake decommitment")]
    VerifyHandshakeError(#[from] SessionProofError),
    #[error("Transcript length mismatch, expected {expected} but got {actual}")]
    TranscriptLengthMismatch { expected: usize, actual: usize },
    #[error(transparent)]
    ProofError(#[from] SubstringProofError),
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
