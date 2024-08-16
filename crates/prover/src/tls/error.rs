use std::error::Error;
use tls_tee::TeeTlsError;

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
    InvalidServerName(#[from] tls_core::dns::InvalidDnsNameError),
    #[error("error occurred in Tee protocol: {0}")]
    TeeError(Box<dyn Error + Send + Sync + 'static>),
    #[error("server did not send a close_notify")]
    ServerNoCloseNotify,
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

impl From<TeeTlsError> for ProverError {
    fn from(e: TeeTlsError) -> Self {
        Self::TeeError(Box::new(e))
    }
}