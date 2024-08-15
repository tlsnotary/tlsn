use std::{error::Error, fmt::Display};

use tls_backend::BackendError;

/// Tee-TLS protocol error.
#[derive(Debug, thiserror::Error)]
#[error("tls error: kind {kind}, msg: {msg}")]
pub struct TeeTlsError {
    kind: Kind,
    msg: String,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl TeeTlsError {
    pub(crate) fn new(kind: Kind, msg: impl ToString) -> Self {
        Self {
            kind,
            msg: msg.to_string(),
            source: None,
        }
    }

    pub(crate) fn other(msg: impl ToString) -> Self {
        Self {
            kind: Kind::Other,
            msg: msg.to_string(),
            source: None,
        }
    }

    pub(crate) fn other_with_source<E>(msg: impl ToString, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind: Kind::Other,
            msg: msg.to_string(),
            source: Some(source.into()),
        }
    }

    /// Returns the error message.
    pub fn msg(&self) -> &str {
        &self.msg
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// The kind of Tee-TLS error that occurred
pub(crate) enum Kind {
    State,
    /// IO related error
    Io,
    /// Peer misbehaved somehow, perhaps maliciously.
    PeerMisbehaved,
    /// Other error
    Other,
}

impl Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kind::State => write!(f, "State"),
            Kind::Io => write!(f, "Io"),
            Kind::PeerMisbehaved => write!(f, "PeerMisbehaved"),
            Kind::Other => write!(f, "Other"),
        }
    }
}

impl From<std::io::Error> for TeeTlsError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: Kind::Io,
            msg: "io error".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<ludi::MessageError> for TeeTlsError {
    fn from(err: ludi::MessageError) -> Self {
        match err {
            ludi::MessageError::Closed => Self::other("actor channel closed"),
            ludi::MessageError::Interrupted => Self::other("actor interrupted during handling"),
            _ => Self::other_with_source("unknown actor error", err),
        }
    }
}

impl From<TeeTlsError> for BackendError {
    fn from(err: TeeTlsError) -> Self {
        BackendError::InternalError(err.to_string())
    }
}
