//! Notary client errors.
//!
//! This module handles errors that might occur during connection setup and
//! notarization requests.

use derive_builder::UninitializedFieldError;
use std::{error::Error, fmt};

#[derive(Debug)]
#[allow(missing_docs)]
pub(crate) enum ErrorKind {
    Internal,
    Builder,
    Connection,
    TlsSetup,
    Http,
    Configuration,
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub struct ClientError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ClientError {
    pub(crate) fn new(kind: ErrorKind, source: Option<Box<dyn Error + Send + Sync>>) -> Self {
        Self { kind, source }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "client error: {:?}, source: {:?}",
            self.kind, self.source
        )
    }
}

impl From<UninitializedFieldError> for ClientError {
    fn from(ufe: UninitializedFieldError) -> Self {
        ClientError::new(ErrorKind::Builder, Some(Box::new(ufe)))
    }
}
