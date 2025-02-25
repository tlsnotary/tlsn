use std::fmt::Display;

/// AES error.
#[derive(Debug, thiserror::Error)]
pub struct AesError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl AesError {
    pub(crate) fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ErrorKind {
    Vm,
    Key,
    Iv,
}

impl Display for AesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Vm => write!(f, "vm error")?,
            ErrorKind::Key => write!(f, "key error")?,
            ErrorKind::Iv => write!(f, "iv error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}
