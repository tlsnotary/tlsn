use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use eyre::Report;
use std::error::Error;

use tlsn_verifier::tls::{VerifierConfigBuilderError, VerifierError};

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

/// Trait implementation to convert this error into an axum http response
impl IntoResponse for NotaryServerError {
    fn into_response(self) -> Response {
        match self {
            bad_request_error @ NotaryServerError::BadProverRequest(_) => {
                (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response()
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something wrong happened.",
            )
                .into_response(),
        }
    }
}
