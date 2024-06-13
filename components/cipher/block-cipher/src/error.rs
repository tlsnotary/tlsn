use core::fmt;
use std::error::Error;

use crate::BlockCipherCircuit;

/// A block cipher error.
#[derive(Debug, thiserror::Error)]
pub struct BlockCipherError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl BlockCipherError {
    pub(crate) fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    pub(crate) fn key_not_set() -> Self {
        Self {
            kind: ErrorKind::Key,
            source: Some("key not set".into()),
        }
    }

    pub(crate) fn invalid_message_length<C: BlockCipherCircuit>(len: usize) -> Self {
        Self {
            kind: ErrorKind::Msg,
            source: Some(
                format!(
                    "message length does not equal block length: {} != {}",
                    len,
                    C::BLOCK_LEN
                )
                .into(),
            ),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ErrorKind {
    Vm,
    Key,
    Msg,
}

impl fmt::Display for BlockCipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Vm => write!(f, "vm error")?,
            ErrorKind::Key => write!(f, "key error")?,
            ErrorKind::Msg => write!(f, "message error")?,
        }

        if let Some(ref source) = self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<mpz_garble::MemoryError> for BlockCipherError {
    fn from(error: mpz_garble::MemoryError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::LoadError> for BlockCipherError {
    fn from(error: mpz_garble::LoadError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::ExecutionError> for BlockCipherError {
    fn from(error: mpz_garble::ExecutionError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::DecodeError> for BlockCipherError {
    fn from(error: mpz_garble::DecodeError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}
