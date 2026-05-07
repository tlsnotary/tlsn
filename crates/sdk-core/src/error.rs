//! Error types for the SDK.

use std::fmt;

/// Result type for SDK operations.
pub type Result<T> = std::result::Result<T, SdkError>;

/// Error type for SDK operations.
#[derive(Debug)]
pub struct SdkError {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

/// The kind of SDK error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Invalid state for the requested operation.
    InvalidState,
    /// Configuration error.
    Config,
    /// IO error.
    Io,
    /// Protocol error.
    Protocol,
    /// HTTP error.
    Http,
    /// Handler processing error.
    Handler,
    /// Internal error.
    Internal,
}

impl SdkError {
    /// Creates a new SDK error.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    /// Creates a new SDK error with a source error.
    pub fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Returns the error kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Creates an invalid state error.
    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidState, message)
    }

    /// Creates a config error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config, message)
    }

    /// Creates an IO error.
    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, message)
    }

    /// Creates a protocol error.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, message)
    }

    /// Creates an HTTP error.
    pub fn http(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Http, message)
    }

    /// Creates a handler processing error.
    pub fn handler(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Handler, message)
    }

    /// Creates an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, message)
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for SdkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for SdkError {
    fn from(err: std::io::Error) -> Self {
        Self::with_source(ErrorKind::Io, "IO error", err)
    }
}

impl From<hyper::Error> for SdkError {
    fn from(err: hyper::Error) -> Self {
        Self::with_source(ErrorKind::Http, "HTTP error", err)
    }
}

impl From<hyper::http::Error> for SdkError {
    fn from(err: hyper::http::Error) -> Self {
        Self::with_source(ErrorKind::Http, "HTTP error", err)
    }
}

impl From<tlsn::Error> for SdkError {
    fn from(err: tlsn::Error) -> Self {
        Self::with_source(ErrorKind::Protocol, "Protocol error", err)
    }
}

impl From<tlsn::config::tls_commit::mpc::MpcTlsConfigError> for SdkError {
    fn from(err: tlsn::config::tls_commit::mpc::MpcTlsConfigError) -> Self {
        Self::with_source(ErrorKind::Config, "MPC TLS config error", err)
    }
}

impl From<tlsn::config::prover::ProverConfigError> for SdkError {
    fn from(err: tlsn::config::prover::ProverConfigError) -> Self {
        Self::with_source(ErrorKind::Config, "Prover config error", err)
    }
}

impl From<tlsn::config::tls::TlsConfigError> for SdkError {
    fn from(err: tlsn::config::tls::TlsConfigError) -> Self {
        Self::with_source(ErrorKind::Config, "TLS config error", err)
    }
}

impl From<tlsn::config::tls_commit::proxy::ProxyTlsConfigError> for SdkError {
    fn from(err: tlsn::config::tls_commit::proxy::ProxyTlsConfigError) -> Self {
        Self::with_source(ErrorKind::Config, "Proxy TLS config error", err)
    }
}

impl From<tlsn::config::verifier::VerifierConfigError> for SdkError {
    fn from(err: tlsn::config::verifier::VerifierConfigError) -> Self {
        Self::with_source(ErrorKind::Config, "Verifier config error", err)
    }
}

impl From<tlsn::config::prove::ProveConfigError> for SdkError {
    fn from(err: tlsn::config::prove::ProveConfigError) -> Self {
        Self::with_source(ErrorKind::Config, "Prove config error", err)
    }
}
