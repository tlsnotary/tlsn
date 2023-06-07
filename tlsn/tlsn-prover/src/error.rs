use std::error::Error;

use tlsn_tls_mpc::MpcTlsError;

/// An error that can occur during proving.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ProverError {
    #[error(transparent)]
    TlsClientError(#[from] tls_client::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error(transparent)]
    CoreError(#[from] tlsn_core::Error),
    #[error(transparent)]
    InvalidServerName(#[from] tls_core::dns::InvalidDnsNameError),
    #[error("error occurred in MPC protocol: {0}")]
    MpcError(Box<dyn Error + Send + 'static>),
    #[error("Prover is already running")]
    AlreadyRunning,
    #[error("Unable to close TLS connection")]
    CloseTlsConnection,
    #[error("server did not send a close_notify")]
    ServerNoCloseNotify,
    #[error("Prover has already been shutdown")]
    AlreadyShutdown,
    #[error(transparent)]
    CommitmentError(#[from] CommitmentError),
}

impl From<MpcTlsError> for ProverError {
    fn from(e: MpcTlsError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

#[derive(Debug)]
pub struct OTShutdownError;

impl std::fmt::Display for OTShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ot shutdown prior to completion")
    }
}

impl Error for OTShutdownError {}

impl From<OTShutdownError> for ProverError {
    fn from(e: OTShutdownError) -> Self {
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
