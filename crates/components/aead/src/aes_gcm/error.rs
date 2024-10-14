use std::fmt::Display;

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
    BlockCipher,
    StreamCipher,
    Ghash,
    Tag,
    PeerMisbehaved,
    Payload,
}

impl Display for AesGcmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Io => write!(f, "io error")?,
            ErrorKind::BlockCipher => write!(f, "block cipher error")?,
            ErrorKind::StreamCipher => write!(f, "stream cipher error")?,
            ErrorKind::Ghash => write!(f, "ghash error")?,
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

impl From<block_cipher::BlockCipherError> for AesGcmError {
    fn from(err: block_cipher::BlockCipherError) -> Self {
        Self::new(ErrorKind::BlockCipher, err)
    }
}

impl From<tlsn_stream_cipher::StreamCipherError> for AesGcmError {
    fn from(err: tlsn_stream_cipher::StreamCipherError) -> Self {
        Self::new(ErrorKind::StreamCipher, err)
    }
}

impl From<tlsn_universal_hash::UniversalHashError> for AesGcmError {
    fn from(err: tlsn_universal_hash::UniversalHashError) -> Self {
        Self::new(ErrorKind::Ghash, err)
    }
}
