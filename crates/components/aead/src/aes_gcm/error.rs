use std::{error::Error, fmt::Display};

use mpz_memory_core::binary::Binary;

/// AES-GCM error.
#[derive(Debug, thiserror::Error)]
pub struct AesGcmError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl AesGcmError {
    pub(crate) fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub(crate) fn invalid_tag() -> Self {
        Self {
            kind: ErrorKind::Tag,
            source: None,
        }
    }

    pub(crate) fn peer(reason: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::PeerMisbehaved,
            source: Some(reason.into().into()),
        }
    }

    pub(crate) fn payload(reason: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Payload,
            source: Some(reason.into().into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ErrorKind {
    Io,
    Ghash,
    Key,
    Iv,
    StartCtr,
    Zero,
    Vm,
    Tag,
    PeerMisbehaved,
    Payload,
}

impl Display for AesGcmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Io => write!(f, "io error")?,
            ErrorKind::Ghash => write!(f, "ghash error")?,
            ErrorKind::Key => write!(f, "key error")?,
            ErrorKind::Iv => write!(f, "iv error")?,
            ErrorKind::StartCtr => write!(f, "start ctr error")?,
            ErrorKind::Zero => write!(f, "zero block error")?,
            ErrorKind::Vm => write!(f, "vm error")?,
            ErrorKind::Tag => write!(f, "payload has corrupted tag")?,
            ErrorKind::PeerMisbehaved => write!(f, "peer misbehaved")?,
            ErrorKind::Payload => write!(f, "payload error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<std::io::Error> for AesGcmError {
    fn from(err: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, err)
    }
}

impl From<tlsn_universal_hash::UniversalHashError> for AesGcmError {
    fn from(err: tlsn_universal_hash::UniversalHashError) -> Self {
        Self::new(ErrorKind::Ghash, err)
    }
}
