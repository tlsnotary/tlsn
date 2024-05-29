//! Notary client errors.
//!
//! This module handles errors that might occur during connection setup and notarization requests

use derive_builder::UninitializedFieldError;
use std::{error::Error, fmt};

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub struct ClientError {
    kind: ErrorKind,
    msg: Option<String>,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ClientError {
    pub(crate) fn new(
        kind: ErrorKind,
        msg: Option<String>,
        source: Option<Box<dyn Error + Send + Sync>>,
    ) -> Self {
        Self { kind, msg, source }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client error: {:?}, msg: {:?}", self.kind, self.msg)
    }
}

#[derive(Debug)]
#[allow(missing_docs)]
pub(crate) enum ErrorKind {
    Unexpected,
    Builder,
    Connection,
    TlsSetup,
    Configuration,
    NotarizationRequest,
}

impl From<UninitializedFieldError> for ClientError {
    fn from(ufe: UninitializedFieldError) -> Self {
        ClientError::new(ErrorKind::Builder, None, Some(Box::new(ufe)))
    }
}
