use std::error::Error;

use tls_mpc::MpcTlsError;

/// An error that can occur during notarization.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum NotaryError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error(transparent)]
    CoreError(#[from] tlsn_core::Error),
    #[error("error occurred in MPC protocol: {0}")]
    MpcError(Box<dyn Error + Send + 'static>),
}

impl From<MpcTlsError> for NotaryError {
    fn from(e: MpcTlsError) -> Self {
        Self::MpcError(Box::new(e))
    }
}
