use std::{error::Error, fmt::Display};

use tls_backend::BackendError;

/// MPC-TLS protocol error.
#[derive(Debug, thiserror::Error)]
#[error("mpc-tls error: kind {kind}, msg: {msg}")]
pub struct MpcTlsError {
    kind: Kind,
    msg: String,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl MpcTlsError {
    pub(crate) fn new(kind: Kind, msg: impl ToString) -> Self {
        Self {
            kind,
            msg: msg.to_string(),
            source: None,
        }
    }

    pub(crate) fn new_with_source<E>(kind: Kind, msg: impl ToString, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            msg: msg.to_string(),
            source: Some(source.into()),
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
/// The kind of MPC-TLS error that occurred
pub(crate) enum Kind {
    /// An unexpected state was encountered
    State,
    /// Context error.
    Ctx,
    /// IO related error
    Io,
    /// An error occurred during MPC
    Mpc,
    /// An error occurred during key exchange
    KeyExchange,
    /// An error occurred during PRF
    Prf,
    /// An error occurred during encryption
    Encrypt,
    /// An error occurred during decryption
    Decrypt,
    /// An error related to configuration.
    Config,
    /// Peer misbehaved somehow, perhaps maliciously.
    PeerMisbehaved,
    /// Other error
    Other,
}

impl Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kind::State => write!(f, "State"),
            Kind::Ctx => write!(f, "Context"),
            Kind::Io => write!(f, "Io"),
            Kind::Mpc => write!(f, "Mpc"),
            Kind::KeyExchange => write!(f, "KeyExchange"),
            Kind::Prf => write!(f, "Prf"),
            Kind::Encrypt => write!(f, "Encryption"),
            Kind::Decrypt => write!(f, "Decryption"),
            Kind::Config => write!(f, "Config"),
            Kind::PeerMisbehaved => write!(f, "PeerMisbehaved"),
            Kind::Other => write!(f, "Other"),
        }
    }
}

impl From<std::io::Error> for MpcTlsError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: Kind::Io,
            msg: "io error".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<ludi::MessageError> for MpcTlsError {
    fn from(err: ludi::MessageError) -> Self {
        match err {
            ludi::MessageError::Closed => Self::other("actor channel closed"),
            ludi::MessageError::Interrupted => Self::other("actor interrupted during handling"),
            _ => Self::other_with_source("unknown actor error", err),
        }
    }
}

impl From<mpz_common::ContextError> for MpcTlsError {
    fn from(err: mpz_common::ContextError) -> Self {
        Self {
            kind: Kind::Ctx,
            msg: "context error".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<mpz_garble::VmError> for MpcTlsError {
    fn from(err: mpz_garble::VmError) -> Self {
        Self {
            kind: Kind::Mpc,
            msg: "mpc-vm error".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<key_exchange::KeyExchangeError> for MpcTlsError {
    fn from(err: key_exchange::KeyExchangeError) -> Self {
        Self {
            kind: Kind::KeyExchange,
            msg: "key exchange error".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<hmac_sha256::PrfError> for MpcTlsError {
    fn from(err: hmac_sha256::PrfError) -> Self {
        Self {
            kind: Kind::Prf,
            msg: "prf error".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<MpcTlsError> for BackendError {
    fn from(err: MpcTlsError) -> Self {
        BackendError::InternalError(err.to_string())
    }
}
