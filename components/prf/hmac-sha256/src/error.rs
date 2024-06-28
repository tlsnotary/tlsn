use core::fmt;
use std::error::Error;

/// A PRF error.
#[derive(Debug, thiserror::Error)]
pub struct PrfError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl PrfError {
    pub(crate) fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
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
    Vm,
    State,
    Role,
}

impl fmt::Display for PrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Vm => write!(f, "vm error")?,
            ErrorKind::State => write!(f, "state error")?,
            ErrorKind::Role => write!(f, "role error")?,
        }

        if let Some(ref source) = self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<mpz_garble::MemoryError> for PrfError {
    fn from(error: mpz_garble::MemoryError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::LoadError> for PrfError {
    fn from(error: mpz_garble::LoadError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::ExecutionError> for PrfError {
    fn from(error: mpz_garble::ExecutionError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::DecodeError> for PrfError {
    fn from(error: mpz_garble::DecodeError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}
