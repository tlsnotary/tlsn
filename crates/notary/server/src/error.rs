use axum::http::StatusCode;
use axum_core::response::{IntoResponse as AxumCoreIntoResponse, Response};
use eyre::Report;
use std::error::Error;
use tlsn_common::config::ProtocolConfigValidatorBuilderError;

use tlsn_verifier::{VerifierConfigBuilderError, VerifierError};

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
    #[error(transparent)]
    Unexpected(#[from] Report),
    #[error("Failed to connect to prover: {0}")]
    Connection(String),
    #[error("Error occurred during notarization: {0}")]
    Notarization(Box<dyn Error + Send + 'static>),
    #[error("Invalid request from prover: {0}")]
    BadProverRequest(String),
    #[error("Unauthorized request from prover: {0}")]
    UnauthorizedProverRequest(String),
}

impl From<VerifierError> for NotaryServerError {
    fn from(error: VerifierError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

impl From<VerifierConfigBuilderError> for NotaryServerError {
    fn from(error: VerifierConfigBuilderError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

impl From<ProtocolConfigValidatorBuilderError> for NotaryServerError {
    fn from(error: ProtocolConfigValidatorBuilderError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

/// Trait implementation to convert this error into an axum http response
impl AxumCoreIntoResponse for NotaryServerError {
    fn into_response(self) -> Response {
        match self {
            bad_request_error @ NotaryServerError::BadProverRequest(_) => {
                (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response()
            }
            unauthorized_request_error @ NotaryServerError::UnauthorizedProverRequest(_) => (
                StatusCode::UNAUTHORIZED,
                unauthorized_request_error.to_string(),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something wrong happened.",
            )
                .into_response(),
        }
    }
}
