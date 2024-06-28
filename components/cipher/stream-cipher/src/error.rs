use core::fmt;
use std::error::Error;

use crate::CtrCircuit;

/// A stream cipher error.
#[derive(Debug, thiserror::Error)]
pub struct StreamCipherError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl StreamCipherError {
    pub(crate) fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    pub(crate) fn key_len<C: CtrCircuit>(len: usize) -> Self {
        Self {
            kind: ErrorKind::Key,
            source: Some(
                format!("invalid key length: expected {}, got {}", C::KEY_LEN, len).into(),
            ),
        }
    }

    pub(crate) fn iv_len<C: CtrCircuit>(len: usize) -> Self {
        Self {
            kind: ErrorKind::Iv,
            source: Some(format!("invalid iv length: expected {}, got {}", C::IV_LEN, len).into()),
        }
    }

    pub(crate) fn explicit_nonce_len<C: CtrCircuit>(len: usize) -> Self {
        Self {
            kind: ErrorKind::ExplicitNonce,
            source: Some(
                format!(
                    "invalid explicit nonce length: expected {}, got {}",
                    C::NONCE_LEN,
                    len
                )
                .into(),
            ),
        }
    }

    pub(crate) fn key_not_set() -> Self {
        Self {
            kind: ErrorKind::Key,
            source: Some("key not set".into()),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ErrorKind {
    Vm,
    Key,
    Iv,
    ExplicitNonce,
}

impl fmt::Display for StreamCipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Vm => write!(f, "vm error")?,
            ErrorKind::Key => write!(f, "key error")?,
            ErrorKind::Iv => write!(f, "iv error")?,
            ErrorKind::ExplicitNonce => write!(f, "explicit nonce error")?,
        }

        if let Some(ref source) = self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<mpz_garble::MemoryError> for StreamCipherError {
    fn from(error: mpz_garble::MemoryError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::LoadError> for StreamCipherError {
    fn from(error: mpz_garble::LoadError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::ExecutionError> for StreamCipherError {
    fn from(error: mpz_garble::ExecutionError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::ProveError> for StreamCipherError {
    fn from(error: mpz_garble::ProveError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::VerifyError> for StreamCipherError {
    fn from(error: mpz_garble::VerifyError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}

impl From<mpz_garble::DecodeError> for StreamCipherError {
    fn from(error: mpz_garble::DecodeError) -> Self {
        Self::new(ErrorKind::Vm, error)
    }
}
