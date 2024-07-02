use std::error::Error;
use tls_mpc::MpcTlsError;
use tlsn_core::commitment::TranscriptCommitmentBuilderError;

/// An error that can occur during proving.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ProverError {
    #[error(transparent)]
    TlsClientError(#[from] tls_client::Error),
    #[error(transparent)]
    AsyncClientError(#[from] tls_client_async::ConnectionError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("notarization error: {0}")]
    NotarizationError(String),
    #[error(transparent)]
    CommitmentBuilder(#[from] TranscriptCommitmentBuilderError),
    #[error(transparent)]
    InvalidServerName(#[from] tls_core::dns::InvalidDnsNameError),
    #[error("error occurred in MPC protocol: {0}")]
    MpcError(Box<dyn Error + Send + Sync + 'static>),
    #[error("server did not send a close_notify")]
    ServerNoCloseNotify,
    #[error(transparent)]
    CommitmentError(#[from] CommitmentError),
    #[error("Range exceeds transcript length")]
    InvalidRange,
}

impl From<uid_mux::yamux::ConnectionError> for ProverError {
    fn from(e: uid_mux::yamux::ConnectionError) -> Self {
        Self::IOError(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            e,
        ))
    }
}

impl From<mpz_common::ContextError> for ProverError {
    fn from(e: mpz_common::ContextError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<MpcTlsError> for ProverError {
    fn from(e: MpcTlsError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::OTError> for ProverError {
    fn from(e: mpz_ot::OTError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::kos::SenderError> for ProverError {
    fn from(e: mpz_ot::kos::SenderError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ole::OLEError> for ProverError {
    fn from(e: mpz_ole::OLEError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::kos::ReceiverError> for ProverError {
    fn from(e: mpz_ot::kos::ReceiverError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::VmError> for ProverError {
    fn from(e: mpz_garble::VmError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::protocol::deap::DEAPError> for ProverError {
    fn from(e: mpz_garble::protocol::deap::DEAPError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::MemoryError> for ProverError {
    fn from(e: mpz_garble::MemoryError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::ProveError> for ProverError {
    fn from(e: mpz_garble::ProveError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<tlsn_core::merkle::MerkleError> for ProverError {
    fn from(e: tlsn_core::merkle::MerkleError) -> Self {
        Self::CommitmentError(e.into())
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum CommitmentError {
    #[error(transparent)]
    MerkleError(#[from] tlsn_core::merkle::MerkleError),
}
