use core::fmt;
use std::error::Error;

use mpz_hash::sha256::Sha256Error;

/// An error type used by the functionalities of this crate.
#[derive(Debug, thiserror::Error)]
pub struct FError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl FError {
    pub(crate) fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    pub(crate) fn vm<E: Into<Box<dyn Error + Send + Sync>>>(err: E) -> Self {
        Self::new(ErrorKind::Vm, err)
    }

    pub(crate) fn state(msg: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::State,
            source: Some(msg.into().into()),
        }
    }
}

impl From<Sha256Error> for FError {
    fn from(value: Sha256Error) -> Self {
        Self::new(ErrorKind::Hash, value)
    }
}

#[derive(Debug)]
pub(crate) enum ErrorKind {
    Vm,
    State,
    Hash,
}

impl fmt::Display for FError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Vm => write!(f, "vm error")?,
            ErrorKind::State => write!(f, "state error")?,
            ErrorKind::Hash => write!(f, "hash error")?,
        }

        if let Some(ref source) = self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}
