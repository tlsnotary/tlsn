use std::error::Error;
use tls_tee::TeeTlsError;

/// An error that can occur during TLS verification.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VerifierError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("error occurred in Tee protocol: {0}")]
    TeeError(Box<dyn Error + Send + Sync + 'static>),
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

impl From<TeeTlsError> for VerifierError {
    fn from(e: TeeTlsError) -> Self {
        Self::TeeError(Box::new(e))
    }
}
