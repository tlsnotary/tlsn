use std::error::Error;

/// MPC-TLS protocol error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct KeyExchangeError(#[from] pub(crate) ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("key exchange error: {0}")]
pub(crate) enum ErrorRepr {
    #[error("state error: {0}")]
    State(Box<dyn Error + Send + Sync + 'static>),
    #[error("context error: {0}")]
    Ctx(Box<dyn Error + Send + Sync + 'static>),
    #[error("io error: {0}")]
    Io(std::io::Error),
    #[error("vm error: {0}")]
    Vm(Box<dyn Error + Send + Sync + 'static>),
    #[error("share conversion error: {0}")]
    ShareConversion(Box<dyn Error + Send + Sync + 'static>),
    #[error("role error: {0}")]
    Role(Box<dyn Error + Send + Sync + 'static>),
    #[error("key error: {0}")]
    Key(Box<dyn Error + Send + Sync + 'static>),
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
