use crate::leader::state::StateError;
use std::{error::Error, fmt::Display};

/// MPC-TLS protocol error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct MpcTlsError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    /// An unexpected state was encountered
    State(Box<dyn Error + Send + Sync + 'static>),
    /// Context error.
    Ctx(Box<dyn Error + Send + Sync + 'static>),
    /// IO related error
    Io(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during key exchange
    KeyExchange(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during PRF
    Prf(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during encryption
    Encrypt(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during decryption
    Decrypt(Box<dyn Error + Send + Sync + 'static>),
    /// An error related to configuration.
    Config(Box<dyn Error + Send + Sync + 'static>),
    /// Peer misbehaved somehow, perhaps maliciously.
    PeerMisbehaved(Box<dyn Error + Send + Sync + 'static>),
    /// Virtual machine error
    Vm(Box<dyn Error + Send + Sync + 'static>),
    /// Backend error
    Backend(Box<dyn Error + Send + Sync + 'static>),
    /// Decoding error
    Decode(Box<dyn Error + Send + Sync + 'static>),
    /// Other error
    Other(Box<dyn Error + Send + Sync + 'static>),
}

impl Display for ErrorRepr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorRepr::State(error) => write!(f, "{error}"),
            ErrorRepr::Ctx(error) => write!(f, "{error}"),
            ErrorRepr::Io(error) => write!(f, "{error}"),
            ErrorRepr::KeyExchange(error) => write!(f, "{error}"),
            ErrorRepr::Prf(error) => write!(f, "{error}"),
            ErrorRepr::Encrypt(error) => write!(f, "{error}"),
            ErrorRepr::Decrypt(error) => write!(f, "{error}"),
            ErrorRepr::Config(error) => write!(f, "{error}"),
            ErrorRepr::PeerMisbehaved(error) => write!(f, "{error}"),
            ErrorRepr::Vm(error) => write!(f, "{error}"),
            ErrorRepr::Backend(error) => write!(f, "{error}"),
            ErrorRepr::Decode(error) => write!(f, "{error}"),
            ErrorRepr::Other(error) => write!(f, "{error}"),
        }
    }
}

impl MpcTlsError {
    pub(crate) fn state<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::State(err.into()))
    }

    pub(crate) fn ctx<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Ctx(err.into()))
    }

    pub(crate) fn io<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Io(err.into()))
    }

    pub(crate) fn key_exchange<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::KeyExchange(err.into()))
    }

    pub(crate) fn prf<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Prf(err.into()))
    }

    pub(crate) fn encrypt<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Encrypt(err.into()))
    }

    pub(crate) fn decrypt<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Decrypt(err.into()))
    }

    pub(crate) fn config<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Config(err.into()))
    }

    pub(crate) fn peer<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::PeerMisbehaved(err.into()))
    }

    pub(crate) fn vm<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }

    pub(crate) fn backend<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Backend(err.into()))
    }

    pub(crate) fn decode<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Decode(err.into()))
    }

    pub(crate) fn other<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Other(err.into()))
    }
}

impl From<StateError> for MpcTlsError {
    fn from(value: StateError) -> Self {
        MpcTlsError::state(value)
    }
}
