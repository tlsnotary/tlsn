//! Notary client errors.
//!
//! This module handles errors that might occur during prover setup

use derive_builder::UninitializedFieldError;
use eyre::Report;
use std::error::Error;
use tlsn_prover::tls::{ProverConfigBuilderError, ProverError};

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum NotaryClientError {
    #[error(transparent)]
    Unexpected(#[from] Report),
    #[error("Failed to build notary client: {0}")]
    Builder(String),
    #[error("Failed to connect to notary: {0}")]
    Connection(String),
    #[error("Error occured when setting up TLS to connect to notary: {0}")]
    TlsSetup(String),
    #[error("Error occurred during configuration: {0}")]
    Configuration(String),
    #[error("Error occurred during notarization request: {0}")]
    NotarizationRequest(String),
    #[error("Error occurred during prover setup: {0}")]
    ProverSetup(Box<dyn Error + Send + 'static>),
}

impl From<ProverError> for NotaryClientError {
    fn from(error: ProverError) -> Self {
        Self::ProverSetup(Box::new(error))
    }
}

impl From<ProverConfigBuilderError> for NotaryClientError {
    fn from(error: ProverConfigBuilderError) -> Self {
        Self::ProverSetup(Box::new(error))
    }
}

impl From<UninitializedFieldError> for NotaryClientError {
    fn from(ufe: UninitializedFieldError) -> Self {
        Self::Builder(ufe.to_string())
    }
}
