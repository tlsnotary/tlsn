use std::{error::Error, fmt::Display};

/// MPC-TLS protocol error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct KeyExchangeError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
pub(crate) enum ErrorRepr {
    /// An unexpected state was encountered
    State(Box<dyn Error + Send + Sync + 'static>),
    /// Context error.
    Ctx(Box<dyn Error + Send + Sync + 'static>),
    /// IO related error
    Io(std::io::Error),
    /// Virtual machine error
    Vm(Box<dyn Error + Send + Sync + 'static>),
    /// Share conversion error
    ShareConversion(Box<dyn Error + Send + Sync + 'static>),
    /// Role error
    Role(Box<dyn Error + Send + Sync + 'static>),
    /// Key error
    Key(Box<dyn Error + Send + Sync + 'static>),
}

impl Display for ErrorRepr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorRepr::State(error) => write!(f, "{error}"),
            ErrorRepr::Ctx(error) => write!(f, "{error}"),
            ErrorRepr::Io(error) => write!(f, "{error}"),
            ErrorRepr::Vm(error) => write!(f, "{error}"),
            ErrorRepr::ShareConversion(error) => write!(f, "{error}"),
            ErrorRepr::Role(error) => write!(f, "{error}"),
            ErrorRepr::Key(error) => write!(f, "{error}"),
        }
    }
}

impl KeyExchangeError {
    pub(crate) fn state<E>(err: E) -> KeyExchangeError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::State(err.into()))
    }

    pub(crate) fn ctx<E>(err: E) -> KeyExchangeError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Ctx(err.into()))
    }

    pub(crate) fn vm<E>(err: E) -> KeyExchangeError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }

    pub(crate) fn share_conversion<E>(err: E) -> KeyExchangeError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::ShareConversion(err.into()))
    }

    pub(crate) fn role<E>(err: E) -> KeyExchangeError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Role(err.into()))
    }

    pub(crate) fn key<E>(err: E) -> KeyExchangeError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Key(err.into()))
    }

    #[cfg(test)]
    pub(crate) fn kind(&self) -> &ErrorRepr {
        &self.0
    }
}

impl From<mpz_common::ContextError> for KeyExchangeError {
    fn from(value: mpz_common::ContextError) -> Self {
        Self::ctx(value)
    }
}

impl From<p256::elliptic_curve::Error> for KeyExchangeError {
    fn from(value: p256::elliptic_curve::Error) -> Self {
        Self::key(value)
    }
}

impl From<std::io::Error> for KeyExchangeError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}
