use core::fmt;
use std::error::Error;

/// A key exchange error.
#[derive(Debug, thiserror::Error)]
pub struct KeyExchangeError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl KeyExchangeError {
    pub(crate) fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub(crate) fn state(msg: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::State,
            source: Some(msg.into().into()),
        }
    }

    pub(crate) fn role(msg: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Role,
            source: Some(msg.into().into()),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ErrorKind {
    Io,
    Context,
    Vm,
    ShareConversion,
    Key,
    State,
    Role,
}

impl fmt::Display for KeyExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Io => write!(f, "io error")?,
            ErrorKind::Context => write!(f, "context error")?,
            ErrorKind::Vm => write!(f, "vm error")?,
            ErrorKind::ShareConversion => write!(f, "share conversion error")?,
            ErrorKind::Key => write!(f, "key error")?,
            ErrorKind::State => write!(f, "state error")?,
            ErrorKind::Role => write!(f, "role error")?,
        }

        if let Some(ref source) = self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<mpz_common::ContextError> for KeyExchangeError {
    fn from(error: mpz_common::ContextError) -> Self {
        Self::new(ErrorKind::Context, error)
    }
}

impl From<mpz_garble::MemoryError> for KeyExchangeError {
    fn from(error: mpz_garble::MemoryError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::LoadError> for KeyExchangeError {
    fn from(error: mpz_garble::LoadError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::ExecutionError> for KeyExchangeError {
    fn from(error: mpz_garble::ExecutionError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::DecodeError> for KeyExchangeError {
    fn from(error: mpz_garble::DecodeError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_share_conversion::ShareConversionError> for KeyExchangeError {
    fn from(error: mpz_share_conversion::ShareConversionError) -> Self {
        Self::new(ErrorKind::ShareConversion, error)
    }
}

impl From<p256::elliptic_curve::Error> for KeyExchangeError {
    fn from(error: p256::elliptic_curve::Error) -> Self {
        Self::new(ErrorKind::Key, error)
    }
}

impl From<std::io::Error> for KeyExchangeError {
    fn from(error: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, error)
    }
}
