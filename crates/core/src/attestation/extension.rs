use std::error::Error;

use serde::{Deserialize, Serialize};

use crate::hash::impl_domain_separator;

/// An attestation extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Extension {
    /// Extension identifier.
    pub id: Vec<u8>,
    /// Extension data.
    pub value: Vec<u8>,
}

impl_domain_separator!(Extension);

/// Invalid extension error.
#[derive(Debug, thiserror::Error)]
#[error("invalid extension: {reason}")]
pub struct InvalidExtension {
    reason: Box<dyn Error + Send + Sync + 'static>,
}

impl InvalidExtension {
    /// Creates a new invalid extension error.
    pub fn new<E>(reason: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self {
            reason: reason.into(),
        }
    }
}
